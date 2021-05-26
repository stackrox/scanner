package ziputil

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
)

// Extract extracts the given target file or directory from the source ZIP file
// and writes the contents to the destination file or directory.
func Extract(source, target, destination string) error {
	target = filepath.Clean(target)

	rc, err := zip.OpenReader(source)
	if err != nil {
		return errors.Wrapf(err, "opening reader for zip %s", source)
	}
	defer utils.IgnoreError(rc.Close)

	for _, f := range rc.File {
		if within(target, f.Name) {
			if err := extractFile(destination, f); err != nil {
				return errors.Wrapf(err, "extracting file %s from zip %s", f.Name, source)
			}
		}
	}

	return nil
}

func extractFile(destination string, file *zip.File) error {
	path := filepath.Join(destination, file.Name)

	if file.FileInfo().IsDir() {
		return os.MkdirAll(path, file.Mode())
	}

	out, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "creating %s", path)
	}
	defer utils.IgnoreError(out.Close)

	err = out.Chmod(file.Mode())
	if err != nil {
		return errors.Wrapf(err, "chmod for %s", path)
	}

	f, err := file.Open()
	if err != nil {
		return errors.Wrapf(err, "opening %s", file.Name)
	}
	defer utils.IgnoreError(f.Close)

	_, err = io.Copy(out, f)
	return errors.Wrapf(err, "copying %s to %s", file.Name, path)
}

// within returns true if sub is within or equal to parent.
// This function is inspired by https://github.com/mholt/archiver/blob/v3.5.0/archiver.go#L360
func within(parent, sub string) bool {
	if parent == sub {
		return true
	}
	rel, err := filepath.Rel(parent, sub)
	if err != nil {
		return false
	}
	return !strings.Contains(rel, "..")
}
