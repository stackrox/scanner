package ziputil

import (
	"archive/zip"
	"io"

	"github.com/pkg/errors"
)

// OpenFileInZip opens the given file in the zip, and returns the ReadCloser.
// It returns an error if the file was not found, or if there was an error opening
// the file.
func OpenFileInZip(zipR *zip.ReadCloser, name string) (io.ReadCloser, error) {
	for _, file := range zipR.File {
		if file.Name == name {
			return file.Open()
		}
	}
	return nil, errors.Errorf("file %q not found in zip", name)
}
