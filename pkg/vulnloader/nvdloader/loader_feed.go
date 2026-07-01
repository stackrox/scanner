package nvdloader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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

	const maxRetries = 10
	const maxBackoff = 5 * time.Minute
	backoff := 10 * time.Second
	var apiFeed *apischema.CVEAPIJSON20
	for attempt := 1; ; attempt++ {
		var err error
		apiFeed, err = fetchFeed(url, year)
		if err == nil {
			break
		}
		if attempt >= maxRetries {
			return errors.Wrapf(err, "failed to download feed for year %d after %d attempts", year, attempt)
		}
		log.Warnf("Feed year %d: attempt %d failed: %v; retrying in %s", year, attempt, err, backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	cveItems, err := toJSON10(apiFeed.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to convert feed vulns to JSON for year %d: %w", year, err)
	}

	enrichCVEItems(&cveItems, enrichments)

	feed := &jsonschema.NVDCVEFeedJSON10{
		CVEItems: cveItems,
	}
	if err := writeFile(filepath.Join(outputDir, fmt.Sprintf("%d.json", year)), feed); err != nil {
		return errors.Wrapf(err, "writing to file for year %d", year)
	}

	log.Infof("Feed year %d: completed with %d vulnerabilities", year, len(cveItems))
	return nil
}

func fetchFeed(url string, year int) (*apischema.CVEAPIJSON20, error) {
	log.Infof("Downloading NVD feed for year %d from %s", year, url)

	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP request failed (elapsed: %s)", time.Since(start))
	}
	defer utils.IgnoreError(resp.Body.Close)

	log.Infof("Feed year %d: HTTP %d, Content-Length: %d, Proto: %s (connect took %s)",
		year, resp.StatusCode, resp.ContentLength, resp.Proto, time.Since(start))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "creating gzip reader")
	}

	body, err := io.ReadAll(gr)
	if err != nil {
		return nil, errors.Wrapf(err, "reading feed body (read %d bytes, elapsed: %s)", len(body), time.Since(start))
	}
	log.Infof("Feed year %d: read %d decompressed bytes (elapsed: %s)", year, len(body), time.Since(start))

	apiFeed := new(apischema.CVEAPIJSON20)
	if err := json.Unmarshal(body, apiFeed); err != nil {
		return nil, errors.Wrapf(err, "decoding feed JSON (%d bytes)", len(body))
	}

	return apiFeed, nil
}
