package gitarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantOwner   string
		wantRepo    string
		wantErr     bool
	}{
		{
			name:      "HTTPS URL",
			url:       "https://github.com/stackrox/k8s-cves",
			wantOwner: "stackrox",
			wantRepo:  "k8s-cves",
			wantErr:   false,
		},
		{
			name:      "HTTPS URL with .git",
			url:       "https://github.com/stackrox/istio-cves.git",
			wantOwner: "stackrox",
			wantRepo:  "istio-cves",
			wantErr:   false,
		},
		{
			name:      "Git protocol",
			url:       "git://github.com/stackrox/dotnet-scraper",
			wantOwner: "stackrox",
			wantRepo:  "dotnet-scraper",
			wantErr:   false,
		},
		{
			name:      "No protocol prefix",
			url:       "github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:    "Invalid format - no repo",
			url:     "https://github.com/owner",
			wantErr: true,
		},
		{
			name:    "Invalid format - empty",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantOwner, owner)
				assert.Equal(t, tt.wantRepo, repo)
			}
		})
	}
}


func TestExtractDirectory(t *testing.T) {
	// Create a test ZIP in memory
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Add files to the ZIP
	files := map[string]string{
		"repo-main/README.md":       "# README",
		"repo-main/cves/CVE-001.yaml": "id: CVE-001",
		"repo-main/cves/CVE-002.yaml": "id: CVE-002",
		"repo-main/cves/sub/CVE-003.yaml": "id: CVE-003",
		"repo-main/other/file.txt":  "other file",
	}

	for name, content := range files {
		w, err := zipWriter.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}

	err := zipWriter.Close()
	require.NoError(t, err)

	// Create ZIP reader
	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	// Test extracting cves directory
	tempDir, err := os.MkdirTemp("", "extract-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	err = ExtractDirectory(zipReader, "repo-main/cves", tempDir)
	require.NoError(t, err)

	// Verify extracted files
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, entries, 3) // CVE-001.yaml, CVE-002.yaml, sub/

	// Verify file contents
	content, err := os.ReadFile(filepath.Join(tempDir, "CVE-001.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "id: CVE-001", string(content))

	// Verify subdirectory
	subEntries, err := os.ReadDir(filepath.Join(tempDir, "sub"))
	require.NoError(t, err)
	assert.Len(t, subEntries, 1)
}

func TestExtractDirectory_NonExistentSource(t *testing.T) {
	// Create empty ZIP
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	err := zipWriter.Close()
	require.NoError(t, err)

	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "extract-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Try to extract non-existent directory
	err = ExtractDirectory(zipReader, "nonexistent/", tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "source directory not found")
}

func TestExtractDirectory_PathTraversalPrevention(t *testing.T) {
	// Create a malicious ZIP with path traversal attempt
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Try to create a file with path traversal
	w, err := zipWriter.Create("repo-main/../../../etc/passwd")
	require.NoError(t, err)
	_, err = w.Write([]byte("malicious"))
	require.NoError(t, err)

	err = zipWriter.Close()
	require.NoError(t, err)

	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "extract-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Extraction should fail due to path traversal attempt
	err = ExtractDirectory(zipReader, "repo-main", tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestFetch_Integration(t *testing.T) {
	// Skip in short mode and CI
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	result, err := Fetch(ctx, FetchOptions{
		RepoURL: "https://github.com/stackrox/k8s-cves",
		Ref:     "main",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ZipReader)

	// Verify ZIP contains expected structure
	found := false
	for _, file := range result.ZipReader.File {
		if file.Name == "k8s-cves-main/README.md" || file.Name == "k8s-cves-main/cves/" {
			found = true
			break
		}
	}
	assert.True(t, found, "ZIP should contain expected files")

	// Cleanup
	err = result.Cleanup()
	assert.NoError(t, err)
}

