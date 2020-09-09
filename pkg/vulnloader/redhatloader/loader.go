package redhatloader

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

func init() {
	vulnloader.RegisterLoader(vulndump.RedHatDirName, &loader{})
}

const (
	cvesPerPage = 30000
)

var (
	client = http.Client{
		Timeout:   3 * time.Minute,
		Transport: proxy.RoundTripper(),
	}
)

type loader struct{}

// DownloadFeedsToPath downloads the Red Hat feeds to the given path.
// If this function is successful, it will fill the directory with
// one json file for each page of the Red Hat data.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	redhatDir := filepath.Join(outputDir, vulndump.RedHatDirName)
	if err := os.MkdirAll(redhatDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", vulndump.RedHatDirName)
	}

	for page, done := 1, false; !done; page++ {
		var err error
		if done, err = downloadFeedForPage(redhatDir, page); err != nil {
			return err
		}
	}

	return nil
}

func downloadFeedForPage(outputDir string, page int) (bool, error) {
	url := jsonFeedURLForPage(page)
	resp, err := client.Get(url)
	if err != nil {
		return false, errors.Wrapf(err, "failed to download feed for page %d", page)
	}
	defer utils.IgnoreError(resp.Body.Close)

	path := filepath.Join(outputDir, fmt.Sprintf("%d.json", page))
	outF, err := os.Create(path)
	if err != nil {
		return false, errors.Wrapf(err, "failed to create file %s", path)
	}
	defer utils.IgnoreError(outF.Close)

	n, err := io.Copy(outF, resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "copying resp body to file")
	}

	// Empty pages return empty JSON lists, [].
	if n == 2 {
		return true, os.Remove(path)
	}

	return false, nil
}

func jsonFeedURLForPage(page int) string {
	return fmt.Sprintf("https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=%d&page=%d", cvesPerPage, page)
}
