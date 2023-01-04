package ziputil

import (
	"archive/zip"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/fsutil"
)

// ReadCloser is a wrapper around io.ReadCloser for reading files in a ZIP.
type ReadCloser struct {
	io.ReadCloser
	Name string
}

// OpenFile opens the given file in the zip, and returns the ReadCloser.
// It returns an error if the file was not found, or if there was an error opening
// the file.
func OpenFile(zipR *zip.Reader, name string) (*ReadCloser, error) {
	for _, file := range zipR.File {
		if file.Name == name {
			f, err := file.Open()
			if err != nil {
				return nil, err
			}

			return &ReadCloser{
				ReadCloser: f,
				Name:       name,
			}, nil
		}
	}
	return nil, errors.Errorf("file %q not found in zip", name)
}

// OpenFilesInDir opens the files with the given suffix which are in the given dir.
// It returns an error if any of the files cannot be opened.
func OpenFilesInDir(zipR *zip.Reader, dir string, suffix string) ([]*ReadCloser, error) {
	var rs []*ReadCloser
	for _, file := range zipR.File {
		if fsutil.Within(dir, file.Name) && strings.HasSuffix(file.Name, suffix) {
			f, err := file.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "unable to open file %s in directory %s", file.Name, dir)
			}
			rs = append(rs, &ReadCloser{
				ReadCloser: f,
				Name:       file.Name,
			})
		}
	}

	return rs, nil
}
