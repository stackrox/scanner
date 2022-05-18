package elf

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/ioutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsELFExecutable(t *testing.T) {
	testCases := []struct {
		path  string
		isELF bool
	}{
		{
			path:  "testdata/elf_exec",
			isELF: true,
		},
		{
			path:  "testdata/macho_exec",
			isELF: false,
		},
		{
			path:  "testdata/README.md",
			isELF: false,
		},
	}
	for _, c := range testCases {
		t.Run(c.path, func(t *testing.T) {
			elfFile, err := os.Open(c.path)
			require.NoError(t, err)
			metadata, err := GetExecutableMetadata(elfFile)
			assert.NoError(t, err)
			if c.isELF {
				assert.NotNil(t, metadata)
			} else {
				assert.Nil(t, metadata)
			}
		})
	}
}

type badReader struct{}

func (br *badReader) ReadAt(p []byte, _ int64) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, io.ErrNoProgress
}

func TestErrorHandling(t *testing.T) {
	metadata, err := GetExecutableMetadata(&badReader{})
	require.Nil(t, metadata)
	require.ErrorIs(t, err, io.ErrNoProgress)
}

func TestGetImportedLibraries(t *testing.T) {
	elfFile := "testdata/elf_exec"
	stat, err := os.Stat(elfFile)
	require.NoError(t, err)
	fileSize := stat.Size()

	// Emulate analyzing files with different initial buffer capacity.
	bufSizes := []int64{63, 64, fileSize - 1, fileSize - 64, fileSize, 64, 1}
	var buf []byte
	var lzReader ioutils.LazyReaderAtWithDiskBackedBuffer
	defer func() {
		if lzReader != nil {
			_ = lzReader.Close()
		}
	}()
	file, err := os.Open("testdata/elf_exec")
	assert.NoError(t, err)
	defer utils.IgnoreError(file.Close)
	for _, bufSize := range bufSizes {
		_, err := file.Seek(0, io.SeekStart)
		assert.NoError(t, err)
		fmt.Printf("Testing with max buffer size: %d\n", bufSize)
		if lzReader != nil {
			buf = lzReader.StealBuffer()
			_ = lzReader.Close()
		}
		lzReader = ioutils.NewLazyReaderAtWithDiskBackedBuffer(file, fileSize, buf, bufSize)
		assert.NoError(t, err)
		elfMetadata, err := GetExecutableMetadata(lzReader)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(elfMetadata.ImportedLibraries))
		assert.Zero(t, len(elfMetadata.Sonames))
	}
}
