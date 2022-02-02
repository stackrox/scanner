package ioutils

import (
	"context"
	"io"
	"sync"
)

type lazyReaderAtWithBufferPool struct {
	reader io.Reader
	size   int64

	mutex sync.RWMutex
	err   error

	buffer *Buffer
}

type LazyReaderAtWithBufferPool interface {
	io.ReaderAt
	FreeBuffer()
}

func NewLazyReaderAtWithBufferPool(reader io.Reader, size int64, bufferPool *BufferPool) (LazyReaderAtWithBufferPool, error) {
	buf, err := bufferPool.MakeBuffer()
	if err != nil {
		return nil, err
	}
	return &lazyReaderAtWithBufferPool{
		reader: reader,
		size:   size,
		buffer: buf,
	}, nil
}

func (r *lazyReaderAtWithBufferPool) FreeBuffer() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.buffer.Free()
}

func (r *lazyReaderAtWithBufferPool) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n, err := r.tryReadAt(p, off)
	if n != 0 || err != nil {
		return n, err
	}

	if err := r.readUntil(off + int64(len(p))); err != nil {
		return 0, err
	}

	return r.tryReadAt(p, off)
}

func (r *lazyReaderAtWithBufferPool) tryReadAt(p []byte, off int64) (int, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	pos := r.buffer.Len()
	if off+int64(len(p)) <= pos {
		return r.buffer.Copy(p, off), nil
	}

	if r.err != nil {
		// If we are in error state, that means we have read as much as we could from the reader.
		// Read whatever is left in the buffer, accompanied by the error.
		if off >= r.buffer.Len() {
			return 0, r.err
		}
		return r.buffer.Copy(p, off), r.err
	}

	return 0, nil
}

func (r *lazyReaderAtWithBufferPool) readUntil(pos int64) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if pos > r.size {
		pos = r.size
	}

	if pos <= r.buffer.Len() {
		return nil
	}

	if bufSize := r.buffer.Cap(); bufSize < pos {
		// Grow the buffer to the size required
		if err := r.buffer.Grow(context.Background(), pos-bufSize); err != nil {
			return err
		}
	}

	oldPos := r.buffer.Len()
	_, err := r.buffer.ReadFullFromReader(r.reader, oldPos, pos)
	if err != nil {
		r.err = err
	} else if pos == r.size {
		r.err = io.EOF
	}
	return nil
}
