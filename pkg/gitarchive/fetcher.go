package gitarchive

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/httputil"
)

// FetchResult contains the downloaded archive and cleanup function.
type FetchResult struct {
	// ZipReader for reading files from the archive
	ZipReader *zip.Reader

	// Cleanup function to delete temporary files
	Cleanup func() error
}

// FetchOptions configures the ZIP download behavior.
type FetchOptions struct {
	// GitHub repository URL (e.g., "https://github.com/stackrox/k8s-cves")
	RepoURL string

	// Branch/ref to download (e.g., "main", "master")
	Ref string
}

// Fetch downloads a GitHub repository as a ZIP archive.
// The archive is downloaded to a temporary file to avoid loading
// everything into memory. The Cleanup function must be called to
// remove the temporary file.
func Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	owner, repo, err := parseGitHubURL(opts.RepoURL)
	if err != nil {
		return nil, errors.Wrap(err, "parsing GitHub URL")
	}

	// Format: https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip
	archiveURL := fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/%s.zip",
		owner, repo, opts.Ref)

	resp, err := httputil.GetWithUserAgent(archiveURL)
	if err != nil {
		return nil, errors.Wrapf(err, "downloading archive from %s", archiveURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("HTTP %d: failed to download archive from %s",
			resp.StatusCode, archiveURL)
	}

	// ZIP format requires random access (io.ReaderAt), so we use a temp file
	// rather than streaming or loading everything into memory
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("%s-%s-*.zip", repo, opts.Ref))
	if err != nil {
		return nil, errors.Wrap(err, "creating temporary file")
	}

	size, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, errors.Wrap(err, "writing archive to temp file")
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, errors.Wrap(err, "seeking to beginning of temp file")
	}

	zipReader, err := zip.NewReader(tmpFile, size)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, errors.Wrap(err, "creating ZIP reader")
	}

	return &FetchResult{
		ZipReader: zipReader,
		Cleanup: func() error {
			tmpFile.Close()
			return os.Remove(tmpFile.Name())
		},
	}, nil
}

// parseGitHubURL extracts owner and repository name from a GitHub URL.
// Supports formats:
// - https://github.com/owner/repo
// - https://github.com/owner/repo.git
// - git://github.com/owner/repo
func parseGitHubURL(url string) (owner, repo string, err error) {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "github.com/")
	url = strings.TrimSuffix(url, ".git")

	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", "", errors.Errorf("invalid GitHub URL format: %s", url)
	}

	return parts[0], parts[1], nil
}

