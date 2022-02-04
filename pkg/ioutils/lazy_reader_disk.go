package ioutils

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/mathutil"
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

	mutex   sync.RWMutex
	file    *os.File
	dirPath string
	err     error
}

// NewLazyReaderAtWithDiskBackedBuffer creates a LazyBuffer implementation with the size of buffer limited.
// We cache the first maxBufferSize of data in the buffer and offload the remaining data to a file on disk.
func NewLazyReaderAtWithDiskBackedBuffer(reader io.Reader, size int64, buf []byte, maxBufferSize int64) LazyReaderAt {
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
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Clean up
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	if r.dirPath != "" {
		_ = os.RemoveAll(r.dirPath)
	}

	r.err = errBufferStolen
	return r.lzReader.StealBuffer()
}

func (r *diskBackedLazyReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}

	// Both LazyReader and os.File handle EOF. So we do not check reading overflow here.
	if r.size > r.maxBufferSize && off+int64(len(p)) > r.maxBufferSize {
		r.overflowToDisk()
	}

	return r.readAt(p, off)
}

func (r *diskBackedLazyReaderAt) readAt(p []byte, off int64) (n int, err error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if off < r.maxBufferSize {
		n, err = r.lzReader.ReadAt(p[:mathutil.MinInt64(int64(len(p)), r.maxBufferSize-off)], off)
		if err != nil || n == len(p) {
			return
		}
	}
	if r.file != nil {
		// Fill the rest from disk. Offset is relative to r.maxBufferSize.
		var nFromDisk int
		nFromDisk, err = r.file.ReadAt(p[n:], off+int64(n)-r.maxBufferSize)
		n += nFromDisk
	}

	if n == len(p) {
		return n, nil
	}

	if r.err != nil {
		// If we are in error state, return the bytes read and the error state.
		return n, r.err
	}

	if off+int64(len(p)) > r.size {
		return n, io.EOF
	}
	return
}

func (r *diskBackedLazyReaderAt) overflowToDisk() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.err != nil || r.file != nil {
		return
	}

	// Forcefully fill up the lazyReader buffer by reading the last byte.
	buf := make([]byte, 1)
	_, err := r.lzReader.ReadAt(buf, r.maxBufferSize-1)
	if err != nil {
		r.err = err
		return
	}

	r.dirPath, err = os.MkdirTemp("", tmpDirName)
	if err != nil {
		r.err = errors.Wrap(err, "failed to create temp dir for overflow")
		return
	}
	defer func() {
		if r.file == nil {
			_ = os.RemoveAll(r.dirPath)
			r.dirPath = ""
		}
	}()

	// Prepare overflow file
	filePath := filepath.Join(r.dirPath, tmpFileName)
	r.file, err = os.Create(filePath)
	if err != nil {
		r.err = errors.Wrapf(err, "create overflow file %s", filePath)
		return
	}

	_, r.err = io.CopyN(r.file, r.reader, r.size-r.maxBufferSize)
}
