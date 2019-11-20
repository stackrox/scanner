package server

import (
	"io"

	"github.com/pkg/errors"
)

type layerDownloadReadCloser struct {
	io.ReadCloser
	downloader func() (io.ReadCloser, error)
}

func (l *layerDownloadReadCloser) Read(p []byte) (int, error) {
	if l.ReadCloser == nil {
		readCloser, err := l.downloader()
		if err != nil {
			return 0, errors.Wrap(err, "error downloading layer")
		}
		l.ReadCloser = readCloser
	}
	return l.ReadCloser.Read(p)
}

func (l *layerDownloadReadCloser) Close() error {
	if l.ReadCloser != nil {
		return l.ReadCloser.Close()
	}
	return nil
}
