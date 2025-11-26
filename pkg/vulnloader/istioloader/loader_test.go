package istioloader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadFeedsToPath(t *testing.T) {
	// Skip this test in short mode or CI as it requires network access
	if testing.Short() {
		t.Skip("Skipping test that requires network access")
	}

	// Create temporary directory for test output
	tempDir, err := os.MkdirTemp("", "istio-loader-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create loader instance
	l := &loader{}

	// Test downloading feeds
	err = l.DownloadFeedsToPath(tempDir)
	require.NoError(t, err, "DownloadFeedsToPath should succeed")

	// Verify the istio directory was created
	istioDir := filepath.Join(tempDir, "istio")
	stat, err := os.Stat(istioDir)
	require.NoError(t, err, "istio directory should exist")
	assert.True(t, stat.IsDir(), "istio should be a directory")

	// Verify the directory contains files
	entries, err := os.ReadDir(istioDir)
	require.NoError(t, err, "should be able to read istio directory")
	assert.NotEmpty(t, entries, "istio directory should contain files")
}

func TestDownloadFeedsToPath_InvalidOutputDir(t *testing.T) {
	l := &loader{}

	// Test with invalid output directory (non-existent parent)
	invalidDir := "/nonexistent/path/to/output"
	err := l.DownloadFeedsToPath(invalidDir)
	assert.Error(t, err, "should fail with invalid output directory")
}
