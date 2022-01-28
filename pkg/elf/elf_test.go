package elf

import (
	"fmt"
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

func TestGetImportedLibraries(t *testing.T) {
	elfFile := "testdata/elf_exec"
	stat, err := os.Stat(elfFile)
	require.NoError(t, err)
	fileSize := stat.Size()

	bufSizes := []int64{64, 1024, fileSize + 128, fileSize - 64, fileSize, 1024, 64}
	var buf []byte
	var lzReader ioutils.LazyReaderAt
	for _, bufSize := range bufSizes {
		file, err := os.Open("testdata/elf_exec")
		defer utils.IgnoreError(file.Close)
		fmt.Printf("Testing with max buffer size: %d\n", bufSize)
		if lzReader != nil {
			buf = lzReader.StealBuffer()
		}
		lzReader = ioutils.NewDiskBackedLazyReaderAtWithBuffer(file, fileSize, buf, bufSize)
		assert.NoError(t, err)
		elfMetadata, err := GetExecutableMetadata(lzReader)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(elfMetadata.ImportedLibraries))
		assert.Zero(t, len(elfMetadata.Sonames))
		file.Close()
	}
	_ = lzReader.StealBuffer()
}
