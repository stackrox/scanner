package elf

import (
	"github.com/stackrox/scanner/pkg/ioutils"
	//"github.com/stackrox/scanner/pkg/ioutils"
	"os"
	"testing"

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
	file, err := os.Open("/Users/cong/go/src/github.com/stackrox/scanner/scc")
	assert.NoError(t, err)
	stat, _ := file.Stat()
	var buf []byte
	lzReader := ioutils.NewDiskBackedLazyReaderAtWithBuffer(file, stat.Size(), buf, 1024)
	// lzReader := ioutils.NewLazyReaderAtWithBuffer(file, stat.Size(), buf)
	elfMetadata, err := GetExecutableMetadata(lzReader)
	assert.NoError(t, err)
	assert.NotZero(t, len(elfMetadata.ImportedLibraries))
	assert.Zero(t, len(elfMetadata.Sonames))
}
