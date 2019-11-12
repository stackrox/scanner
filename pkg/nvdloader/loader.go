package nvdloader

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	client = http.Client{Timeout: 2 * time.Minute}
)

// DownloadFeedsToPath downloads the NVD feeds to the given path.
// The directory must exist already.
// If this function is successful, it will fill the directory with
// one json file for each year of NVD data.
func DownloadFeedsToPath(outputDir string) error {
	endYear := time.Now().Year()
	for year := 2002; year <= endYear; year++ {
		if err := downloadFeedForYear(outputDir, year); err != nil {
			return err
		}
	}
	return nil
}

func downloadFeedForYear(outputDir string, year int) error {
	url := jsonFeedURLForYear(year)
	resp, err := client.Get(url)
	if err != nil {
		return errors.Wrapf(err, "failed to download feed for year %d", year)
	}
	defer utils.IgnoreError(resp.Body.Close)
	// Un-gzip it.
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "couldn't read resp body for year %d", year)
	}
	outF, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("%d.json", year)))
	if err != nil {
		return errors.Wrap(err, "failed to create file")
	}
	defer utils.IgnoreError(outF.Close)
	_, err = io.Copy(outF, gr)
	if err != nil {
		return errors.Wrap(err, "copying resp body to file")
	}
	return nil
}

func jsonFeedURLForYear(year int) string {
	return fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
}
