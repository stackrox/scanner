package gitarchive

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/fsutil"
)

// ExtractDirectory extracts a specific directory from a ZIP archive to disk.
// srcDir is the directory path within the ZIP (e.g., "k8s-cves-main/cves")
// destDir is the destination path on disk where files will be extracted.
//
// Security: This function validates paths to prevent directory traversal attacks.
func ExtractDirectory(zipReader *zip.Reader, srcDir, destDir string) error {
	srcDir = strings.TrimSuffix(srcDir, "/") + "/"

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return errors.Wrapf(err, "creating destination directory: %s", destDir)
	}

	found := false

	for _, file := range zipReader.File {
		if !strings.HasPrefix(file.Name, srcDir) {
			continue
		}

		relPath := strings.TrimPrefix(file.Name, srcDir)
		if relPath == "" {
			continue
		}

		found = true
		destPath := filepath.Join(destDir, relPath)

		if !fsutil.Within(destDir, destPath) {
			return errors.Errorf("invalid file path (potential path traversal): %s", file.Name)
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, file.Mode()); err != nil {
				return errors.Wrapf(err, "creating directory: %s", destPath)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return errors.Wrapf(err, "creating parent directory for: %s", destPath)
		}

		if err := extractFile(file, destPath); err != nil {
			return errors.Wrapf(err, "extracting file: %s", file.Name)
		}
	}

	if !found {
		return errors.Errorf("source directory not found in archive: %s", srcDir)
	}

	return nil
}

func extractFile(file *zip.File, destPath string) error {
	rc, err := file.Open()
	if err != nil {
		return errors.Wrap(err, "opening file from ZIP")
	}
	defer rc.Close()

	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return errors.Wrap(err, "creating destination file")
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, rc); err != nil {
		return errors.Wrap(err, "copying file contents")
	}

	return nil
}
