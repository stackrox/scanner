package nvdloader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

var (
	client = http.Client{
		Timeout:   2 * time.Minute,
		Transport: proxy.RoundTripper(),
	}
)

func init() {
	vulnloader.RegisterLoader(vulndump.NVDDirName, &loader{})
}

type loader struct{}

// DownloadFeedsToPath downloads the NVD feeds to the given path.
// If this function is successful, it will fill the directory with
// one json file for each year of NVD data.
func (l *loader) DownloadFeedsToPath(outputDir string) error {
	// FetchDotnet NVD enrichment data from curated repos
	enrichmentMap := make(map[string][]*FileFormatWrapper)
	err := FetchDotnet(enrichmentMap)
	if err != nil {
		return errors.Wrap(err, "could not fetch NVD enrichment sources")
	}

	nvdDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", vulndump.NVDDirName)
	}
	endYear := time.Now().Year()
	for year := 2002; year <= endYear; year++ {
		if err := downloadFeedForYear(enrichmentMap, nvdDir, year); err != nil {
			return err
		}
	}
	return nil
}

func downloadFeedForYear(enrichmentMap map[string][]*FileFormatWrapper, outputDir string, year int) error {
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

	// Strip out tabs and newlines for size savings
	dump, err := LoadJSONFileFromReader(gr)
	if err != nil {
		return errors.Wrapf(err, "could not decode json for year %d", year)
	}

	for _, item := range dump.CVEItems {
		var lastModified string
		for _, enrichedEntry := range enrichmentMap[item.CVE.CVEDataMeta.ID] {
			// Add the CPE matches instead of removing for backwards compatibility purposes
			item.Configurations.Nodes = append(item.Configurations.Nodes, &schema.NVDCVEFeedJSON10DefNode{
				CPEMatch: enrichedEntry.AffectedPackages,
				Operator: "OR",
			})
			if enrichedEntry.LastUpdated > lastModified {
				lastModified = enrichedEntry.LastUpdated
			}
		}
		if lastModified != "" {
			item.LastModifiedDate = lastModified
		}
	}

	outF, err := os.Create(filepath.Join(outputDir, fmt.Sprintf("%d.json", year)))
	if err != nil {
		return errors.Wrap(err, "failed to create file")
	}
	defer utils.IgnoreError(outF.Close)

	if err := json.NewEncoder(outF).Encode(&dump); err != nil {
		return errors.Wrapf(err, "could not encode json map for year %d", year)
	}
	return nil
}

func jsonFeedURLForYear(year int) string {
	return fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
}
