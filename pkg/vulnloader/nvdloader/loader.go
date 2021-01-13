package nvdloader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
		if err := downloadFeedForYear(enrichmentMap, nvdDir, year); err != nil {
			return err
		}
	}
	return nil
}

func getYearFromCVE(cve string) string {
	spl := strings.Split(cve, "-")
	if len(spl) < 3 {
		return ""
	}
	return spl[1]
}

func downloadFeedForYear(enrichmentMap map[string]*CVEDefinitionWrapper, outputDir string, year int) error {
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
		if enrichedEntry, ok := enrichmentMap[item.CVE.CVEDataMeta.ID]; ok {
			// Add the CPE matches instead of removing for backwards compatibility purposes
			item.Configurations.Nodes = append(item.Configurations.Nodes, &schema.NVDCVEFeedJSON10DefNode{
				CPEMatch: enrichedEntry.AffectedPackages,
				Operator: "OR",
			})
			item.LastModifiedDate = enrichedEntry.LastUpdated
			if item.Impact == nil {
				item.Impact = enrichedEntry.Impact
			} else if item.Impact.BaseMetricV2 == nil && item.Impact.BaseMetricV3 == nil && enrichedEntry.Impact != nil {
				item.Impact = enrichedEntry.Impact
			}
			delete(enrichmentMap, item.CVE.CVEDataMeta.ID)
		}
	}

	yearStr := strconv.Itoa(year)
	for id, enrichedEntry := range enrichmentMap {
		if getYearFromCVE(id) != yearStr {
			continue
		}

		log.Infof("Entry in enrichment map did not exist in NVD file %v: %v", year, id)
		nvdCVE := &schema.NVDCVEFeedJSON10DefCVEItem{
			CVE: &schema.CVEJSON40{
				CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
					ID: id,
				},
				Description: &schema.CVEJSON40Description{
					DescriptionData: []*schema.CVEJSON40LangString{
						{
							Lang:  "en",
							Value: enrichedEntry.Description,
						},
					},
				},
			},
			Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
				Nodes: []*schema.NVDCVEFeedJSON10DefNode{
					{
						CPEMatch: enrichedEntry.AffectedPackages,
						Operator: "OR",
					},
				},
			},
			Impact:           enrichedEntry.Impact,
			LastModifiedDate: enrichedEntry.LastUpdated,
			PublishedDate:    enrichedEntry.LastUpdated,
		}
		dump.CVEItems = append(dump.CVEItems, nvdCVE)
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
