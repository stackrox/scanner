package server

import (
	"io"

	"github.com/pkg/errors"
)

// LayerDownloadReadCloser defines an image layer io.ReadCloser which downloads the layer(s) as needed.
type LayerDownloadReadCloser struct {
	io.ReadCloser
	Downloader func() (io.ReadCloser, error)
}

// Read reads from the reader.
func (l *LayerDownloadReadCloser) Read(p []byte) (int, error) {
	if l.ReadCloser == nil {
		readCloser, err := l.Downloader()
		if err != nil {
			return 0, errors.Wrap(err, "error downloading layer")
		}
		l.ReadCloser = readCloser
	}
	return l.ReadCloser.Read(p)
}

// Close closes the reader.
func (l *LayerDownloadReadCloser) Close() error {
	if l.ReadCloser != nil {
		return l.ReadCloser.Close()
	}
	return nil
}
