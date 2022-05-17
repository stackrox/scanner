package ioutils

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskLazyReader_basic(t *testing.T) {
	overflowBlockSize = 64
	maxBufferSize := int64(100)

	// Random 201 byte string. This string plus a block size of 64 and maxBufferSize of 100 is meant
	// to mimic the actual used values scaled down by a factor of MB.
	testString := `r6stSDxPmOtVZEugG9BWPZ9ftFgFhlIwSj8hVgDVuo0euxQjIerfmH0NnbDVHcnTQbVsvY9dBYAwT4u258UVeEsdrQMujhOgfCX8KLFn6QY4Qmp1gac4Oeh2r6RAmqKmgoExGLAtOngW7Qi5wSzvZeEhC8awmxpzD5Lp5xs1rO6XdDevS0pdnV2yAki7tVrfNFjJYhrNK`
	reader := strings.NewReader(testString)
	lazyReaderAt := NewLazyReaderAtWithDiskBackedBuffer(reader, reader.Size(), []byte{}, maxBufferSize)
	defer func() {
		require.NoError(t, lazyReaderAt.Close())
	}()

	// Read entire contents.
	p := make([]byte, reader.Size())
	n, err := lazyReaderAt.ReadAt(p, 0)
	assert.NoError(t, err)
	assert.Equal(t, int(reader.Size()), n)
	assert.Equal(t, []byte(testString), p)
}

func TestDiskLazyReader(t *testing.T) {
	overflowBlockSize = 30 // Set the overflow block size to something smaller than the test string.

	testString := "This is to create a reader to test lazy reader with disk backed buffer."
	bytes := []byte(testString)
	reader := strings.NewReader(testString)
	dataSize := reader.Size()
	testCases := []int64{1, 2, 3, 4, dataSize - 20, dataSize - 1, dataSize, dataSize + 1, dataSize + 20}
	for _, c := range testCases {
		t.Run(fmt.Sprintf("MaxBufferSize-%d", c), func(t *testing.T) {
			var buf []byte
			_, err := reader.Seek(0, io.SeekStart)
			assert.NoError(t, err)
			lazyReader := NewLazyReaderAtWithDiskBackedBuffer(reader, dataSize, buf, c)

			fetched := make([]byte, dataSize)

			n, err := lazyReader.ReadAt(fetched[:2], 2)
			assert.NoError(t, err)
			assert.Equal(t, fetched[:2], bytes[2:4])
			assert.EqualValues(t, 2, n)

			n, err = lazyReader.ReadAt(fetched[:5], dataSize-5)
			assert.NoError(t, err)
			assert.Equal(t, fetched[:5], bytes[dataSize-5:])
			assert.EqualValues(t, 5, n)

			n, err = lazyReader.ReadAt(fetched, 0)
			assert.NoError(t, err)
			assert.EqualValues(t, dataSize, n)
			assert.Equal(t, bytes, fetched)

			n, err = lazyReader.ReadAt(fetched[:10], dataSize-5)
			assert.Equal(t, io.EOF, err)
			assert.Equal(t, fetched[:5], bytes[dataSize-5:])
			assert.EqualValues(t, 5, n)

			n, err = lazyReader.ReadAt(fetched[:10], dataSize-20)
			assert.NoError(t, err)
			assert.Equal(t, fetched[:10], bytes[dataSize-20:dataSize-10])
			assert.EqualValues(t, 10, n)

			require.NoError(t, lazyReader.Close())
			n, err = lazyReader.ReadAt(fetched[:10], dataSize-10)
			assert.Equal(t, err, errBufferStolen)
			assert.Zero(t, 0, n)
			require.NoError(t, lazyReader.Close())
		})
	}
}
