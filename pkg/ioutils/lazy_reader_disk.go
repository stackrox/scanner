package ioutils

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/mathutil"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	// The temp overFlowFile is like "/tmp/<tmpDirName>111111/<tmpFileName>"
	tmpFileName = "buffer-overflow"
	tmpDirName  = "disk-lazy-reader-"
)

// LazyReaderAtWithDiskBackedBuffer is a LazyReader which uses a temporary file on disk
// to store extra data beyond the maximum buffer size requested.
type LazyReaderAtWithDiskBackedBuffer interface {
	LazyReaderAt
	// Close closes the lazy reader and free any allocated resources.
	Close()
}

// diskBackedLazyReaderAt is a lazy reader backed by disk.
type diskBackedLazyReaderAt struct {
	reader        io.Reader
	lzReader      LazyReaderAt
	size          int64
	maxBufferSize int64

	mutex        sync.RWMutex
	pos          int64
	overFlowFile *os.File
	dirPath      string
	err          error
}

// CleanUpDiskTempFiles removes the temporary overflow files.
func CleanUpDiskTempFiles() {
	dir, err := ioutil.ReadDir(os.TempDir())
	utils.Should(err)
	for _, d := range dir {
		if d.IsDir() && strings.HasPrefix(d.Name(), tmpDirName) {
			_ = os.RemoveAll(filepath.Join(os.TempDir(), d.Name()))
		}
	}
}

// NewLazyReaderAtWithDiskBackedBuffer creates a LazyBuffer implementation with the size of buffer limited.
// We cache the first maxBufferSize of data in the buffer and offload the remaining data to a overFlowFile on disk.
func NewLazyReaderAtWithDiskBackedBuffer(reader io.Reader, size int64, buf []byte, maxBufferSize int64) LazyReaderAtWithDiskBackedBuffer {
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

func (r *diskBackedLazyReaderAt) Close() {
	_ = r.StealBuffer()
}

func (r *diskBackedLazyReaderAt) StealBuffer() []byte {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Clean up
	if r.overFlowFile != nil {
		_ = r.overFlowFile.Close()
		r.overFlowFile = nil
	}
	if r.dirPath != "" {
		_ = os.RemoveAll(r.dirPath)
		r.dirPath = ""
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
	until := off + int64(len(p))
	if r.size > r.maxBufferSize && until > r.maxBufferSize {
		r.overflowToDisk(until)
	}

	return r.readAt(p, off)
}

func (r *diskBackedLazyReaderAt) readAt(p []byte, off int64) (n int, err error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if off < r.maxBufferSize {
		n, err = r.lzReader.ReadAt(p[:mathutil.MinInt64(int64(len(p)), r.maxBufferSize-off)], off)
		if err != nil || n == len(p) {
			return n, err
		}
	}
	if r.overFlowFile != nil {
		// Fill the rest from disk. Offset is relative to r.maxBufferSize.
		var nFromDisk int
		nFromDisk, err = r.overFlowFile.ReadAt(p[n:], off+int64(n)-r.maxBufferSize)
		n += nFromDisk
	}

	if n == len(p) {
		return n, nil
	}

	if r.err != nil {
		// If we are in error state, return the bytes read and the error state.
		return n, r.err
	}

	if err != nil {
		return n, err
	}

	if off+int64(len(p)) > r.size {
		return n, io.EOF
	}
	return n, nil
}

func (r *diskBackedLazyReaderAt) overflowToDisk(till int64) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.err != nil || till <= r.pos {
		return
	}

	if r.pos == 0 {
		// Forcefully fill up the lazyReader buffer by reading the last byte in r.lazyBuffer's buffer.
		buf := make([]byte, 1)
		_, err := r.lzReader.ReadAt(buf, r.maxBufferSize-1)
		if err != nil {
			r.err = err
			return
		}
		r.pos = r.maxBufferSize
	}

	if r.overFlowFile == nil {
		var err error
		r.dirPath, err = os.MkdirTemp("", tmpDirName)
		if err != nil {
			r.err = errors.Wrap(err, "failed to create temp dir for overflow")
			return
		}
		defer func() {
			if r.overFlowFile == nil {
				_ = os.RemoveAll(r.dirPath)
				r.dirPath = ""
			}
		}()

		// Prepare overflow overFlowFile
		filePath := filepath.Join(r.dirPath, tmpFileName)
		r.overFlowFile, err = os.Create(filePath)
		if err != nil {
			r.err = errors.Wrapf(err, "create overflow overFlowFile %s", filePath)
			return
		}
	}

	// Copy until next block align with size r.maxBufferSize or the size of file.
	// Request to copy an extra byte to ensure EOF is recorded.
	to := mathutil.MinInt64(((till-1)/r.maxBufferSize+1)*r.maxBufferSize, r.size)
	if to == r.size {
		to++
	}
	var n int64
	n, r.err = io.CopyN(r.overFlowFile, r.reader, to-r.pos)
	r.pos += n
}
