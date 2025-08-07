package nvdloader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apischema "github.com/facebookincubator/nvdtools/cveapi/nvd/schema"
	jsonschema "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

var _ vulnloader.Loader = (*feedLoader)(nil)

type feedLoader struct{}

// DownloadFeedsToPath downloads the NVD JSON 2.0 feeds to the given path.
// If this function is successful, it will fill the directory with
// one JSON file for each year of NVD data.
func (l *feedLoader) DownloadFeedsToPath(outputDir string) error {
	log.Info("Downloading NVD data using 2.0 Data Feed")

	// Fetch NVD enrichment data from curated repos
	enrichments, err := Fetch()
	if err != nil {
		return errors.Wrap(err, "could not fetch NVD enrichment sources")
	}

	nvdDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", vulndump.NVDDirName)
	}
	endYear := time.Now().Year()
	for year := 2002; year <= endYear; year++ {
		if err := l.downloadFeedForYear(enrichments, nvdDir, year); err != nil {
			return err
		}
	}
	return nil
}

func (l *feedLoader) downloadFeedForYear(enrichments map[string]*FileFormatWrapper, outputDir string, year int) error {
	url := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz", year)
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

	apiFeed := new(apischema.CVEAPIJSON20)
	if err := json.NewDecoder(gr).Decode(apiFeed); err != nil {
		return errors.Wrapf(err, "decoding feed response")
	}

	cveItems, err := toJSON10(apiFeed.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to convert feed vulns to JSON: %w", err)
	}

	enrichCVEItems(&cveItems, enrichments)

	feed := &jsonschema.NVDCVEFeedJSON10{
		CVEItems: cveItems,
	}
	if err := writeFile(filepath.Join(outputDir, fmt.Sprintf("%d.json", year)), feed); err != nil {
		return errors.Wrapf(err, "writing to file")
	}

	return nil
}
