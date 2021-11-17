package elf

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestIsElfExecutable(t *testing.T) {
	testCases := []struct {
		path string
		isElf bool
	}{
		{
			path: "test_data/linux_true",
			isElf: true,
		},
		{
			path: "test_data/macho_true",
			isElf: false,
		},
		{
			path: "test_data/short",
			isElf: false,
		},
	}
	for _, c := range testCases {
		t.Run(c.path, func(t *testing.T) {
			elfFile, err := os.Open(c.path)
			require.NoError(t, err)
			assert.Equal(t, c.isElf, IsKnownExecutable(elfFile))
		})
	}
}

func TestGetNeededLibraries(t *testing.T) {
	elfFile, err := os.Open("test_data/linux_true")
	require.NoError(t, err)
	elfData, err := GetElfData(elfFile)
	assert.NoError(t, err)
	assert.NotZero(t, len(elfData.Dependencies))
	assert.Zero(t, len(elfData.Sonames))
}
