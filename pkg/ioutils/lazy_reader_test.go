package ioutils

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiskLazyReader(t *testing.T) {
	testString := "This is to create a reader to test lazy reader with disk backed buffer."
	bytes := []byte(testString)
	reader := strings.NewReader(testString)
	dataSize := reader.Size()
	testCases := []int64{dataSize - 20, dataSize - 1, dataSize, dataSize + 1, dataSize + 20}
	for _, c := range testCases {
		var buf []byte
		abs, err := reader.Seek(0, io.SeekStart)
		assert.NoError(t, err)
		assert.EqualValues(t, 0, abs)
		lazyReader := NewLazyReaderAtWithDiskBackedBuffer(reader, reader.Size(), buf, c)
		fetched := make([]byte, dataSize)
		n, err := lazyReader.ReadAt(fetched[:5], dataSize-5)
		assert.NoError(t, err)
		assert.EqualValues(t, fetched[:5], bytes[dataSize-5:])
		assert.EqualValues(t, 5, n)

		n, err = lazyReader.ReadAt(fetched, 0)
		assert.NoError(t, err)
		assert.EqualValues(t, dataSize, n)
		assert.Equal(t, bytes, fetched)

		n, err = lazyReader.ReadAt(fetched[:10], dataSize-5)
		assert.Equal(t, io.EOF, err)
		assert.EqualValues(t, fetched[:5], bytes[dataSize-5:])
		assert.EqualValues(t, 5, n)

		n, err = lazyReader.ReadAt(fetched[:10], dataSize-20)
		assert.NoError(t, err)
		assert.EqualValues(t, fetched[:10], bytes[dataSize-20:dataSize-10])
		assert.EqualValues(t, 10, n)

		_ = lazyReader.StealBuffer()
	}
}