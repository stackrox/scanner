package nvdloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	apischema "github.com/facebookincubator/nvdtools/cveapi/nvd/schema"
	jsonschema "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const urlFmt = `https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&startIndex=%d`

var client = http.Client{
	Timeout:   5 * time.Minute,
	Transport: proxy.RoundTripper(),
}

var _ vulnloader.Loader = (*apiLoader)(nil)

type apiLoader struct{}

// DownloadFeedsToPath downloads the NVD 2.0 API data to the given path.
// If this function is successful, it will fill the directory with
// one JSON file for each year of NVD data.
func (l *apiLoader) DownloadFeedsToPath(outputDir string) error {
	log.Info("Downloading NVD data using NVD 2.0 API")

	// Fetch NVD enrichment data from curated repos
	enrichments, err := Fetch()
	if err != nil {
		return fmt.Errorf("could not fetch NVD enrichment sources: %w", err)
	}

	nvdDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdDir, 0755); err != nil {
		return fmt.Errorf("creating subdir for %s: %w", vulndump.NVDDirName, err)
	}

	var fileNo, totalVulns int

	// Explicitly set startIdx to parallel how this is all done within the loop below.
	startIdx := 0
	apiResp, err := query(fmt.Sprintf(urlFmt, startIdx))
	if err != nil {
		return err
	}
	var i int
	// Buffer to store vulns until they are written to a file.
	cveItems := make([]*jsonschema.NVDCVEFeedJSON10DefCVEItem, 0, 20_000)
	for apiResp.ResultsPerPage != 0 {
		vulns, err := toJSON10(apiResp.Vulnerabilities)
		if err != nil {
			return fmt.Errorf("failed to convert API vulns to JSON: %w", err)
		}

		if len(vulns) != 0 {
			cveItems = append(cveItems, vulns...)

			i++
			// Write to disk every ~20,000 vulnerabilities.
			if i == 10 {
				i = 0

				enrichCVEItems(&cveItems, enrichments)

				feed := &jsonschema.NVDCVEFeedJSON10{
					CVEItems: cveItems,
				}
				if err := writeFile(filepath.Join(nvdDir, fmt.Sprintf("%d.json", fileNo)), feed); err != nil {
					return fmt.Errorf("writing to file: %w", err)
				}

				fileNo++
				totalVulns += len(cveItems)
				log.Infof("Loaded %d NVD vulnerabilities", totalVulns)
				// Reduce, reuse, and recycle.
				cveItems = cveItems[:0]
			}
		}

		// Rudimentary rate-limiting.
		// NVD limits users without an API key to roughly one call every 6 seconds.
		// With an API key, it is roughly one call every 0.6 seconds.
		// We'll play it safe and do one call every 3 seconds.
		// As of writing there are ~216,000 vulnerabilities, so this whole process should take ~5.4 minutes.
		time.Sleep(3 * time.Second)

		startIdx += apiResp.ResultsPerPage
		apiResp, err = query(fmt.Sprintf(urlFmt, startIdx))
		if err != nil {
			return err
		}
	}

	// Write the remaining vulnerabilities.
	if len(cveItems) != 0 {
		enrichCVEItems(&cveItems, enrichments)

		feed := &jsonschema.NVDCVEFeedJSON10{
			CVEItems: cveItems,
		}
		if err := writeFile(filepath.Join(nvdDir, fmt.Sprintf("%d.json", fileNo)), feed); err != nil {
			return fmt.Errorf("writing to file: %w", err)
		}

		totalVulns += len(cveItems)
		log.Infof("Loaded %d NVD vulnerabilities", totalVulns)
	}

	return nil
}

func query(url string) (*apischema.CVEAPIJSON20, error) {
	log.Debugf("Querying %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("apiKey", os.Getenv("NVD_API_KEY"))

	apiResp, err := queryWithBackoff(req)
	if err != nil {
		return nil, err
	}

	return apiResp, nil
}

func queryWithBackoff(req *http.Request) (*apischema.CVEAPIJSON20, error) {
	var (
		apiResp *apischema.CVEAPIJSON20
		err     error
	)
	for i := 1; i <= 5; i++ {
		var resp *http.Response
		resp, err = tryQuery(req)
		if err == nil {
			apiResp, err = parseResponse(resp)
			if err == nil {
				break
			}
		}
		log.Warnf("Failed query attempt %d for %s: %v", i, req.URL.String(), err)
		// Wait some multiple of 3 seconds before next attempt.
		time.Sleep(time.Duration(3*i) * time.Second)
	}

	return apiResp, err
}

func tryQuery(req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching NVD API results: %w", err)
	}

	log.Debugf("Queried %s with status code %d", req.URL.String(), resp.StatusCode)
	if resp.StatusCode != 200 {
		utils.IgnoreError(resp.Body.Close)
		return nil, fmt.Errorf("unexpected status code when querying %s: %d", req.URL.String(), resp.StatusCode)
	}

	return resp, nil
}

func parseResponse(resp *http.Response) (*apischema.CVEAPIJSON20, error) {
	defer utils.IgnoreError(resp.Body.Close)

	apiResp := new(apischema.CVEAPIJSON20)
	if err := json.NewDecoder(resp.Body).Decode(apiResp); err != nil {
		return nil, fmt.Errorf("decoding API response: %w", err)
	}

	return apiResp, nil
}

func enrichCVEItems(cveItems *[]*jsonschema.NVDCVEFeedJSON10DefCVEItem, enrichments map[string]*FileFormatWrapper) {
	if cveItems == nil {
		return
	}

	cves := (*cveItems)[:0]
	for _, item := range *cveItems {
		if _, ok := manuallyEnrichedVulns[item.CVE.CVEDataMeta.ID]; ok {
			log.Warnf("Skipping vuln %s because it is being manually enriched", item.CVE.CVEDataMeta.ID)
			continue
		}

		for _, node := range item.Configurations.Nodes {
			removeInvalidCPEs(node)
		}

		if enrichedEntry, ok := enrichments[item.CVE.CVEDataMeta.ID]; ok {
			// Add the CPE matches instead of removing for backwards compatibility purposes
			item.Configurations.Nodes = append(item.Configurations.Nodes, &jsonschema.NVDCVEFeedJSON10DefNode{
				CPEMatch: enrichedEntry.AffectedPackages,
				Operator: "OR",
			})
			item.LastModifiedDate = enrichedEntry.LastUpdated
		}
		cves = append(cves, item)
	}

	for _, item := range manuallyEnrichedVulns {
		cves = append(cves, item)
	}

	*cveItems = cves
}

func removeInvalidCPEs(item *jsonschema.NVDCVEFeedJSON10DefNode) {
	cpeMatches := item.CPEMatch[:0]
	for _, cpeMatch := range item.CPEMatch {
		if cpeMatch.Cpe23Uri == "" {
			cpeMatches = append(cpeMatches, cpeMatch)
			continue
		}
		attr, err := wfn.UnbindFmtString(cpeMatch.Cpe23Uri)
		if err != nil {
			log.Errorf("error parsing %+v", item)
			continue
		}
		if attr.Product == wfn.Any {
			log.Warnf("Filtering out CPE: %+v", attr)
			continue
		}
		cpeMatches = append(cpeMatches, cpeMatch)
	}
	item.CPEMatch = cpeMatches
	for _, child := range item.Children {
		removeInvalidCPEs(child)
	}
}

func writeFile(path string, feed *jsonschema.NVDCVEFeedJSON10) error {
	outF, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", outF.Name(), err)
	}
	defer utils.IgnoreError(outF.Close)

	if err := json.NewEncoder(outF).Encode(feed); err != nil {
		return fmt.Errorf("could not encode JSON for %s: %w", outF.Name(), err)
	}

	return nil
}
