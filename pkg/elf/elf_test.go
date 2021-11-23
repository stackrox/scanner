package elf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsElfExecutable(t *testing.T) {
	testCases := []struct {
		path  string
		isElf bool
	}{
		{
			path:  "testdata/elf_exec",
			isElf: true,
		},
		{
			path:  "testdata/macho_exec",
			isElf: false,
		},
		{
			path:  "testdata/README.md",
			isElf: false,
		},
	}
	for _, c := range testCases {
		t.Run(c.path, func(t *testing.T) {
			elfFile, err := os.Open(c.path)
			require.NoError(t, err)
			if c.isElf {
				assert.NotNil(t, OpenIfElfExecutable(elfFile))
			} else {
				assert.Nil(t, OpenIfElfExecutable(elfFile))
			}
		})
	}
}

func TestGetImportedLibraries(t *testing.T) {
	file, err := os.Open("testdata/elf_exec")
	elfFile := OpenIfElfExecutable(file)
	require.NoError(t, err)
	elfMetadata, err := GetElfMetadata(elfFile)
	assert.NoError(t, err)
	assert.NotZero(t, len(elfMetadata.ImportedLibraries))
	assert.Zero(t, len(elfMetadata.Sonames))
}
