package elf

import (
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
			if c.isELF {
				assert.NotNil(t, OpenIfELFExecutable(elfFile))
			} else {
				assert.Nil(t, OpenIfELFExecutable(elfFile))
			}
		})
	}
}

func TestGetImportedLibraries(t *testing.T) {
	file, err := os.Open("testdata/elf_exec")
	elfFile := OpenIfELFExecutable(file)
	require.NoError(t, err)
	elfMetadata, err := GetELFMetadata(elfFile)
	assert.NoError(t, err)
	assert.NotZero(t, len(elfMetadata.ImportedLibraries))
	assert.Zero(t, len(elfMetadata.Sonames))
}
