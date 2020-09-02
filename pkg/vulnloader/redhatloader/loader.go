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
	"github.com/stackrox/scanner/pkg/vulnloader"
)

func init() {
	vulnloader.RegisterLoader("redhat", &loader{})
}

const (
	cvesPerPage = 30000
)

var (
	client = http.Client{
		Timeout:   2 * time.Minute,
		Transport: proxy.RoundTripper(),
	}
)

type loader struct {}

// DownloadFeedsToPath downloads the Red Hat feeds to the given path.
// The directory must exist already.
// If this function is successful, it will fill the directory with
// one json file for each 1000-item page of the Red Hat data.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	var done bool
	for page := 1; !done; page++ {
		var err error
		if done, err = downloadFeedForPage(outputDir, page); err != nil {
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
	return n == 2, nil
}

func jsonFeedURLForPage(page int) string {
	return fmt.Sprintf("https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=%d&page=%d", cvesPerPage, page)
}
