package ioutils

import (
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/mathutil"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	// The temp file is like "/tmp/<tmpDirName>111111/<tmpFileName>"
	tmpFileName = "buffer-overflow"
	tmpDirName  = "disk-lazy-reader-"
)

// diskBackedLazyReaderAt is a lazy reader backed by disk.
type diskBackedLazyReaderAt struct {
	reader        io.Reader
	lzReader      LazyReaderAt
	size          int64
	maxBufferSize int64

	file    *os.File
	dirPath string
}

// NewDiskBackedLazyReaderAtWithBuffer creates a LazyBuffer implementation with the size of buffer limited.
// We cache the first maxBufferSize of data in the buffer and offload the remaining data to a file on disk.
func NewDiskBackedLazyReaderAtWithBuffer(reader io.Reader, size int64, buf []byte, maxBufferSize int64) LazyReaderAt {
	bufferedSize := size
	if size > maxBufferSize {
		bufferedSize = maxBufferSize
	}
	return &diskBackedLazyReaderAt{
		reader:        reader,
		lzReader:      NewLazyReaderAtWithBuffer(reader, bufferedSize, buf),
		size:          size,
		maxBufferSize: maxBufferSize,
	}
}

func (r *diskBackedLazyReaderAt) StealBuffer() []byte {
	// Clean up
	if r.file != nil {
		_ = r.file.Close()
	}
	if r.dirPath != "" {
		_ = os.RemoveAll(r.dirPath)
	}
	return r.lzReader.StealBuffer()
}

func (r *diskBackedLazyReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}

	if off < r.maxBufferSize {
		bufSize := len(p)
		return r.lzReader.ReadAt(p[:mathutil.MinInt64(int64(bufSize), r.maxBufferSize)], off)
	}

	if r.dirPath == "" {
		var err error
		r.dirPath, err = os.MkdirTemp("", tmpDirName)
		if err != nil {
			return 0, errors.Wrap(err, "failed to create temp dir for overflow")
		}
	}
	defer func() {
		if r.file == nil {
			_ = os.RemoveAll(r.dirPath)
			r.dirPath = ""
		}
	}()

	if r.file == nil {
		filePath := filepath.Join(r.dirPath, tmpFileName)
		outF, err := os.Create(filePath)
		if err != nil {
			return 0, errors.Wrapf(err, "create overflow file %s", filePath)
		}
		defer utils.IgnoreError(outF.Close)

		// Forcefully fill up the lazyReader buffer by reading the last byte.
		buf := make([]byte, 1)
		_, err = r.lzReader.ReadAt(buf, r.maxBufferSize-1)
		if err != nil {
			return 0, err
		}

		_, err = io.Copy(outF, r.reader)
		if err != nil {
			return 0, errors.Wrapf(err, "copy data to overflow file %s", filePath)
		}
		err = outF.Close()
		if err != nil {
			return 0, errors.Wrapf(err, "close disk overflow file %s", filePath)
		}
		inF, err := os.Open(filePath)
		if err != nil {
			return 0, errors.Wrapf(err, "open disk overflow file %s", filePath)
		}
		r.file = inF
	}
	return r.file.ReadAt(p, off-r.maxBufferSize)
}
