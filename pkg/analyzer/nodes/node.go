package nodes

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/detection"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/fsutil/fileinfo"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/metrics"
	"github.com/stackrox/scanner/singletons/requiredfilenames"
)

// Information about extracted files.
type fileMetadata struct {
	// If true, the file is regular and has executable permissions.
	isExecutable bool
	// If true, contents can be extracted from the filesystem.
	isExtractable bool
	// If true, the file is a symlink to some other file.
	isSymlink bool
}

var _ analyzer.Files = (*filesMap)(nil)

// filesMap is an analyzer.Files implementation mapping files extracted from
// filesystem directories. In this implementation the file content is read lazily
// when calls to Get() are made. If an error occurs during content read the map
// will stop returning entries and the error will be available at readErr().
// Analyzer are expected to handle missing files gracefully during analysis and
// check readErr() to confirm all potential data was read.
type filesMap struct {
	// Root directory where all the files, and their relative paths, reside.
	root string
	// Map of extracted file information keyed by their relative file paths.
	files map[string]*fileMetadata
	// Last error found when reading files contents.
	readError error
}

// Components contains the result of a node analysis, listing the OS namespace,
// components and language components.
type Components struct {
	OSNamespace             *database.Namespace
	OSComponents            []database.FeatureVersion
	CertifiedRHELComponents *database.RHELv2Components
	LanguageComponents      []*component.Component
}

// Analyze performs analysis of node's hosts filesystem and return the detected components.
func Analyze(nodeName, rootFSdir string, uncertifiedRHEL bool) (*Components, error) {
	// Currently, the node analyzer can only identify operating system components
	// without active vulnerability, so we use the OS matcher.
	matcher := requiredfilenames.SingletonOSMatcher()
	files, err := extractFilesFromDirectory(rootFSdir, matcher)
	if err != nil {
		return nil, err
	}
	c := &Components{}
	c.OSNamespace, c.OSComponents, c.CertifiedRHELComponents, _, err =
		detection.DetectComponents(nodeName, files, nil, nil, uncertifiedRHEL)
	if err != nil {
		logrus.Error(err)
		return nil, err
	}
	// File reading errors during analysis are not exposed to DetectComponents, hence we
	// check it and if there were any we fail.
	if err := files.readErr(); err != nil {
		return nil, errors.Wrapf(err, "analysis of node %q failed", nodeName)
	}
	return c, nil
}

// extractFilesFromDirectory extracts files from the specified root directory
// using a file matcher.
func extractFilesFromDirectory(root string, matcher matcher.PrefixMatcher) (*filesMap, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid root path %q", root)
	}
	n := &filesMap{
		root:  absRoot,
		files: make(map[string]*fileMetadata),
	}
	m := metrics.FileExtractionMetrics{}
	for _, dir := range matcher.GetCommonPrefixDirs() { //GetAllowList() {
		if err := n.addFiles(filepath.FromSlash(dir), matcher, &m); err != nil {
			return nil, errors.Wrapf(err, "failed to match filesMap at %q (at %q)", dir, n.root)
		}
	}
	m.Emit()
	return n, nil
}

// addFiles searches the directory for files using the matcher and adds them to the file map.
func (n *filesMap) addFiles(dir string, matcher matcher.Matcher, m *metrics.FileExtractionMetrics) error {
	logrus.WithFields(logrus.Fields{
		"root":      n.root,
		"directory": dir,
	}).Info("add files from directory")
	return filepath.WalkDir(filepath.Join(n.root, dir), func(fullPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			if filesIsNotAccessible(err) {
				m.InaccessibleCount()
				return nil
			}
			return errors.Wrapf(err, "failed to read %q", fullPath)
		}
		relPath, err := filepath.Rel(n.root, fullPath)
		if err != nil {
			return errors.Wrapf(err, "walking %q", dir)
		}
		path := filepath.ToSlash(relPath)
		f, err := extractFile(path, entry, matcher, m)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"root":          n.root,
				"directory":     dir,
				"relative_path": relPath,
			}).Error("extract file")
			return err
		}
		logrus.WithFields(logrus.Fields{"path": path, "file": f}).Info("added files from directory")
		if f != nil {
			n.files[path] = f
		}
		return nil
	})
}

// filesIsNotAccessible returns true if the error means the file cannot be read.
func filesIsNotAccessible(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}

// extractFile extracts data from the given directory entry, if granted by the
// path matcher, and if it passes safety checks. Otherwise, returns nil.
func extractFile(path string, entry fs.DirEntry, pathMatcher matcher.Matcher, m *metrics.FileExtractionMetrics) (*fileMetadata, error) {
	// Ignore all directories.
	if entry.IsDir() {
		return nil, nil
	}
	fileInfo, err := entry.Info()
	if err != nil {
		if filesIsNotAccessible(err) {
			m.InaccessibleCount()
			return nil, nil
		}
		// We assume that other errors reflect underlying problems with the filesystem
		// worth failing the whole extraction.
		return nil, err
	}
	m.FileCount()
	// FIXME No matcher actually uses the file contents, except the matcher for
	//       language components, which is not currently used by directory scans, hence we
	//       offer nil.  This will break if a language component matcher (analyzer) is used.
	matches, isExtractable := pathMatcher.Match(path, fileInfo, nil)
	if !matches {
		return nil, nil
	}
	m.MatchCount()
	// File size limit check.
	if isExtractable && fileInfo.Size() > analyzer.GetMaxExtractableFileSize() {
		logrus.Errorf("skipping file %q (%d bytes): size is greater than maxExtractableFileSize of %d MiB",
			path, fileInfo.Size(), analyzer.GetMaxExtractableFileSize()/1024/1024)
		return nil, nil
	}
	return &fileMetadata{
		isExecutable:  fileinfo.IsFileExecutable(fileInfo),
		isExtractable: isExtractable,
		isSymlink:     fileinfo.IsFileSymlink(fileInfo),
	}, nil
}

// Get implements analyzer.Files
func (n *filesMap) Get(path string) (analyzer.FileData, bool) {
	// When a previous read error has happened, we act as if all the files map is
	// empty. Analyzer are expected to handle it gracefully.
	if f, ok := n.files[path]; n.readError == nil && ok {
		fileData := analyzer.FileData{Executable: f.isExecutable}
		if !f.isExtractable {
			return fileData, true
		}
		// Prepend the root to make this an absolute file path.
		absPath := filepath.Join(n.root, filepath.FromSlash(path))
		if f.isSymlink {
			// Resolve the symlink to the correct destination.
			var linkDest string
			linkDest, n.readError = os.Readlink(absPath)
			if n.readError != nil {
				return analyzer.FileData{}, false
			}
			// If the symlink is an absolute path,
			// prepend n.root to the link's destination
			// and read that file, instead.
			// Note: this only matters for symlinks to absolute paths.
			// Symlinks to relative paths are followed correctly.
			if filepath.IsAbs(linkDest) {
				absPath = filepath.Join(n.root, filepath.FromSlash(linkDest))
			}
		}
		fileData.Contents, n.readError = os.ReadFile(absPath)
		if n.readError == nil {
			return fileData, true
		}
	}
	return analyzer.FileData{}, false
}

// GetFilesPrefix implements analyzer.Files
func (n *filesMap) GetFilesPrefix(prefix string) (filesMap map[string]analyzer.FileData) {
	filesMap = make(map[string]analyzer.FileData)
	for name := range n.files {
		if strings.HasPrefix(name, prefix) && name != prefix {
			data, exists := n.Get(name)
			if exists {
				filesMap[name] = data
			}
		}
	}
	return
}

// readErr returns the first error encountered when reading file content, and
// resets the error, enabling re-scans using the same map.
func (n *filesMap) readErr() error {
	err := n.readError
	n.readError = nil
	return err
}
