package nodes

import (
	"context"
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
	"github.com/stackrox/scanner/pkg/fsutil"
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

// AnalyzeOpts contains configuration of how to analyze nodes
type AnalyzeOpts struct {
	// UncertifiedRHEL is boolean to decide if OS is uncertified RHEL
	UncertifiedRHEL bool

	// IsRHCOSRequired: if CoreOS is required for DetectComponents, Node scanning is disabled if false
	IsRHCOSRequired bool
}

// Analyze performs analysis of node's hosts filesystem and return the detected components.
func Analyze(ctx context.Context, nodeName, rootFSdir string, opts AnalyzeOpts) (*Components, error) {
	// Currently, the node analyzer can only identify operating system components
	// without active vulnerability, so we use the OS matcher.
	matcher := requiredfilenames.SingletonOSMatcher()
	files, err := extractFilesFromDirectory(ctx, rootFSdir, matcher)
	if err != nil {
		return nil, err
	}
	c := &Components{}
	c.OSNamespace, c.OSComponents, c.CertifiedRHELComponents, _, err =
		detection.DetectComponents(nodeName, files, nil, nil,
			detection.DetectComponentOpts{UncertifiedRHEL: opts.UncertifiedRHEL, IsRHCOSRequired: opts.IsRHCOSRequired})

	if err != nil {
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
func extractFilesFromDirectory(ctx context.Context, root string, matcher matcher.PrefixMatcher) (*filesMap, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid root path %q", root)
	}
	n := &filesMap{
		root:  absRoot,
		files: make(map[string]*fileMetadata),
	}
	m := metrics.FileExtractionMetrics{}
	// TODO(ROX-13771): Use `range matcher.GetCommonPrefixDirs()` again after fixing.
	for _, dir := range []string{"etc/", "usr/share/rpm", "var/lib/rpm", "usr/share/buildinfo"} {
		if err := n.addFiles(ctx, filepath.FromSlash(dir), matcher, &m); err != nil {
			return nil, errors.Wrapf(err, "failed to match filesMap at %q (at %q)", dir, n.root)
		}
	}
	m.Emit()
	return n, nil
}

func walkDirWithContext(ctx context.Context, dir string, fn fs.WalkDirFunc) error {
	errC := make(chan error)
	go func(ctx context.Context) {
		defer close(errC)
		errC <- filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fn(path, info, err)
			}
		})
	}(ctx)

	// Wait for the WalkDir to complete or for the context to be cancelled.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errC:
		return err
	}
}

// addFiles searches the directory for files using the matcher and adds them to the file map.
// TODO(ROX-14050): Improve handling of symlinks - if possible, follow instead of ignoring them
func (n *filesMap) addFiles(ctx context.Context, dir string, matcher matcher.Matcher, m *metrics.FileExtractionMetrics) error {
	logrus.WithFields(logrus.Fields{
		"root":      n.root,
		"directory": dir,
	}).Info("add files from directory")
	return walkDirWithContext(ctx, filepath.Join(n.root, dir), func(fullPath string, entry fs.DirEntry, err error) error {
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
	f, ok := n.files[path]
	if n.readError != nil || !ok {
		return analyzer.FileData{}, false
	}

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

	// Protect against potentially reading from a path outside root.
	// This is possible when reading a symlinked file.
	if !fsutil.Within(n.root, absPath) {
		return analyzer.FileData{}, false
	}

	fileData.Contents, n.readError = os.ReadFile(absPath)
	if n.readError != nil {
		return analyzer.FileData{}, false
	}

	return fileData, true
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
