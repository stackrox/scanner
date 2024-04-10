package vulndump

import (
	"archive/zip"
	"compress/flate"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/fsutil"
)

// WriteZip takes the given files and creates the vuln dump zip.
func WriteZip(inputDir, outFile string, ignoreKubernetesVulns, ignoreRHELv2Vulns, ignoreIstioVulns bool) error {
	sources := []string{
		filepath.Join(inputDir, ManifestFileName),
		filepath.Join(inputDir, NVDDirName),
		filepath.Join(inputDir, OSVulnsFileName),
	}
	if !ignoreKubernetesVulns {
		sources = append(sources, filepath.Join(inputDir, K8sDirName))
	}
	if !ignoreRHELv2Vulns {
		sources = append(sources, filepath.Join(inputDir, RHELv2DirName))
	}
	if !ignoreIstioVulns {
		sources = append(sources, filepath.Join(inputDir, IstioDirName))
	}
	return archive(sources, outFile)
}

func writeJSONObjectToFile(filePath string, object interface{}) error {
	f, err := os.Create(filePath)
	if err != nil {
		return errors.Wrap(err, "creating file")
	}
	if err := json.NewEncoder(f).Encode(object); err != nil {
		return errors.Wrap(err, "JSON-encoding into file")
	}
	return nil
}

// WriteManifestFile creates and writes the manifest file to the given output dir.
func WriteManifestFile(outputDir string, m Manifest) error {
	if err := writeJSONObjectToFile(filepath.Join(outputDir, ManifestFileName), m); err != nil {
		return errors.Wrap(err, "writing manifest file")
	}
	return nil
}

// WriteOSVulns creates and writes the OS vulns file to the given output dir.
func WriteOSVulns(outputDir string, vulns []database.Vulnerability) error {
	if err := writeJSONObjectToFile(filepath.Join(outputDir, OSVulnsFileName), vulns); err != nil {
		return errors.Wrap(err, "writing os vulns file")
	}
	return nil
}

// archive is an adapted implementation of (*Zip).Archive from
// https://github.com/mholt/archiver/blob/v3.5.1/zip.go#L140
// under MIT License.
func archive(sources []string, destination string) error {
	if !strings.HasSuffix(destination, ".zip") {
		return errors.Errorf("%s must have a .zip extension", destination)
	}
	if fileExists(destination) {
		return errors.Errorf("file already exists: %s", destination)
	}
	dir := filepath.Dir(destination)
	if !fileExists(dir) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrapf(err, "making directory: %s", dir)
		}
	}

	out, err := os.Create(destination)
	if err != nil {
		return errors.Wrapf(err, "creating %s", destination)
	}
	defer utils.IgnoreError(out.Close)

	zipW := zip.NewWriter(out)
	zipW.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	defer utils.IgnoreError(zipW.Close)

	for _, source := range sources {
		err := writeWalk(zipW, source, destination)
		if err != nil {
			return errors.Wrapf(err, "walking %s", source)
		}
	}

	return nil
}

// fileExists is an adapted implementation of fileExists from
// https://github.com/mholt/archiver/blob/v3.5.1/archiver.go#L279
// under MIT License.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// fileInfo is an adapted implementation of FileInfo from
// https://github.com/mholt/archiver/blob/v3.5.1/archiver.go#L125
// under MIT license.
type fileInfo struct {
	os.FileInfo
	customName string
}

func (f fileInfo) Name() string {
	if f.customName != "" {
		return f.customName
	}
	return f.FileInfo.Name()
}

// writeWalk is an adapted implementation of (*Zip).writeWalk from
// https://github.com/mholt/archiver/blob/v3.5.1/zip.go#L300
// under MIT License.
func writeWalk(zipW *zip.Writer, source, destination string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return errors.Wrapf(err, "stat: %s", source)
	}
	destAbs, err := filepath.Abs(destination)
	if err != nil {
		return errors.Wrapf(err, "getting absolute path of destination %s: %s", destination, source)
	}

	return filepath.Walk(source, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.Wrapf(err, "traversing %s", fpath)
		}
		if info == nil {
			return errors.Errorf("%s: no file info", fpath)
		}

		fpathAbs, err := filepath.Abs(fpath)
		if err != nil {
			return errors.Wrapf(err, "%s: getting absolute path", fpath)
		}
		if fsutil.Within(fpathAbs, destAbs) {
			return nil
		}

		// build the name to be used within the archive
		nameInArchive, err := makeNameInArchive(sourceInfo, source, "", fpath)
		if err != nil {
			return err
		}
		finfo := fileInfo{
			FileInfo:   info,
			customName: nameInArchive,
		}

		var file io.ReadCloser
		if finfo.Mode().IsRegular() {
			file, err = os.Open(fpath)
			if err != nil {
				return errors.Wrapf(err, "%s: opening", fpath)
			}
			defer utils.IgnoreError(file.Close)
		}

		header, err := zip.FileInfoHeader(finfo)
		if err != nil {
			return errors.Wrapf(err, "%s: getting header", finfo.Name())
		}

		if finfo.IsDir() {
			header.Name += "/"
		}
		header.Method = zip.Store

		writer, err := zipW.CreateHeader(header)
		if err != nil {
			return errors.Wrapf(err, "%s: making header", finfo.Name())
		}

		if finfo.IsDir() {
			return nil
		}

		_, err = io.Copy(writer, file)
		if err != nil {
			return errors.Wrapf(err, "%s: copying contents", finfo.Name())
		}

		return nil
	})
}

// makeNameInArchive is an adapted implementation of makeNameInArchive from
// https://github.com/mholt/archiver/blob/v3.5.1/archiver.go#L413
// under MIT License.
//
// makeNameInArchive returns the filename for the file given by fpath to be used within
// the archive. sourceInfo is the FileInfo obtained by calling os.Stat on source, and baseDir
// is an optional base directory that becomes the root of the archive. fpath should be the
// unaltered file path of the file given to a filepath.WalkFunc.
func makeNameInArchive(sourceInfo os.FileInfo, source, baseDir, fpath string) (string, error) {
	name := filepath.Base(fpath) // start with the file or dir name
	if sourceInfo.IsDir() {
		// preserve internal directory structure; that's the path components
		// between the source directory's leaf and this file's leaf
		dir, err := filepath.Rel(filepath.Dir(source), filepath.Dir(fpath))
		if err != nil {
			return "", err
		}
		// prepend the internal directory structure to the leaf name,
		// and convert path separators to forward slashes as per spec
		name = path.Join(filepath.ToSlash(dir), name)
	}
	return path.Join(baseDir, name), nil // prepend the base directory
}
