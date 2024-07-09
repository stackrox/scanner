package nvdloader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	rejectedReason = "rejected reason:"
)

var _ vulnloader.Loader = (*legacyLoader)(nil)

type legacyLoader struct{}

// DownloadFeedsToPath downloads the NVD feeds to the given path.
// If this function is successful, it will fill the directory with
// one json file for each year of NVD data.
func (l *legacyLoader) DownloadFeedsToPath(outputDir string) error {
	log.Info("Downloading NVD data using Legacy Data Feed")

	// Fetch NVD enrichment data from curated repos
	enrichmentMap, err := Fetch()
	if err != nil {
		return errors.Wrap(err, "could not fetch NVD enrichment sources")
	}

	nvdDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdDir, 0755); err != nil {
		return errors.Wrapf(err, "creating subdir for %s", vulndump.NVDDirName)
	}
	endYear := time.Now().Year()
	for year := 2002; year <= endYear; year++ {
		if err := l.downloadFeedForYear(enrichmentMap, nvdDir, year); err != nil {
			return err
		}
	}
	return nil
}

func (l *legacyLoader) downloadFeedForYear(enrichmentMap map[string]*FileFormatWrapper, outputDir string, year int) error {
	url := l.jsonFeedURLForYear(year)
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

	cveItems := dump.CVEItems[:0]
	for _, item := range dump.CVEItems {
		if _, ok := manuallyEnrichedVulns[item.CVE.CVEDataMeta.ID]; ok {
			log.Warnf("Skipping vuln %s because it is being manually enriched", item.CVE.CVEDataMeta.ID)
			continue
		}
		if l.rejected(item) {
			log.Warnf("Skipping rejected vuln %q", item.CVE.CVEDataMeta.ID)
			continue
		}
		for _, node := range item.Configurations.Nodes {
			removeInvalidCPEs(node)
		}
		if enrichedEntry, ok := enrichmentMap[item.CVE.CVEDataMeta.ID]; ok {
			// Add the CPE matches instead of removing for backwards compatibility purposes
			item.Configurations.Nodes = append(item.Configurations.Nodes, &schema.NVDCVEFeedJSON10DefNode{
				CPEMatch: enrichedEntry.AffectedPackages,
				Operator: "OR",
			})
			item.LastModifiedDate = enrichedEntry.LastUpdated
		}
		cveItems = append(cveItems, item)
	}
	for _, item := range manuallyEnrichedVulns {
		cveItems = append(cveItems, item)
	}
	dump.CVEItems = cveItems

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

func (l *legacyLoader) rejected(item *schema.NVDCVEFeedJSON10DefCVEItem) bool {
	if item.CVE.Description == nil {
		return false
	}

	for _, desc := range item.CVE.Description.DescriptionData {
		if strings.HasPrefix(strings.ToLower(desc.Value), rejectedReason) {
			return true
		}
	}

	return false
}

func (l *legacyLoader) jsonFeedURLForYear(year int) string {
	return fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
}
