package nvdtoolscache

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
)

func LoadFromDirectory(definitionsDir string) error {
	log.Info("Initializing NVD CPE Definitions")

	extractedPath := filepath.Join(definitionsDir, "cve")
	files, err := ioutil.ReadDir(extractedPath)
	if err != nil {
		return err
	}

	dict := make(cvefeed.Dictionary)
	cveMap := make(map[string]*Vuln)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		if err := handleJSONFile(cveMap, dict, filepath.Join(extractedPath, f.Name())); err != nil {
			return errors.Wrapf(err, "handling file %s", f.Name())
		}
	}
	log.Infof("Total vulns: %d", len(cveMap))

	cache := cvefeed.NewCache(dict).SetMaxSize(-1).SetRequireVersion(false)
	cache.Idx = cvefeed.NewIndex(dict)

	set(cache, cveMap)
	return nil
}

func cpeIsApplication(cpe string) bool {
	spl := strings.SplitN(cpe, ":", 4)
	if len(spl) < 4 {
		return false
	}
	return spl[2] == "a"
}

func isNodeValid(node *schema.NVDCVEFeedJSON10DefNode) bool {
	if len(node.CPEMatch) != 0 {
		filteredCPEs := node.CPEMatch[:0]
		for _, cpe := range node.CPEMatch {
			if cpeIsApplication(cpe.Cpe23Uri) {
				filteredCPEs = append(filteredCPEs, cpe)
			}
		}
		node.CPEMatch = filteredCPEs
		return len(filteredCPEs) != 0
	}
	// Otherwise look at the children and make sure if the Operator is an AND they are all valid
	if strings.EqualFold(node.Operator, "and") {
		for _, c := range node.Children {
			if !isNodeValid(c) {
				return false
			}
		}
		return true
	}
	// Operator is an OR so ensure at least one is valid
	filteredNodes := node.Children[:0]
	for _, c := range node.Children {
		if isNodeValid(c) {
			filteredNodes = append(filteredNodes, c)
		}
	}
	node.Children = filteredNodes
	return len(filteredNodes) != 0
}

func isValidCVE(cve *schema.NVDCVEFeedJSON10DefCVEItem) bool {
	if cve.Configurations == nil {
		return false
	}
	filteredNodes := cve.Configurations.Nodes[:0]
	for _, n := range cve.Configurations.Nodes {
		if isNodeValid(n) {
			filteredNodes = append(filteredNodes, n)
		}
	}
	cve.Configurations.Nodes = filteredNodes
	return len(filteredNodes) != 0
}

func trimCVE(cve *schema.NVDCVEFeedJSON10DefCVEItem) {
	cve.CVE = &schema.CVEJSON40{
		CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
			ID: cve.CVE.CVEDataMeta.ID,
		},
	}
	cve.Configurations = nil
	cve.Impact = nil
	cve.PublishedDate = ""
	cve.LastModifiedDate = ""
}

func handleJSONFile(cveMap map[string]*Vuln, dict cvefeed.Dictionary, path string) error {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer utils.IgnoreError(f.Close)

	var feed schema.NVDCVEFeedJSON10
	if err := json.NewDecoder(f).Decode(&feed); err != nil {
		return err
	}

	for _, cve := range feed.CVEItems {
		if cve != nil && cve.Configurations != nil {
			if !isValidCVE(cve) {
				continue
			}
			vuln := nvd.ToVuln(cve)
			cveMap[vuln.ID()] = &Vuln{
				ID:       vuln.ID(),
				Metadata: convertMetadata(cve),
				Summary:  convertSummary(cve),
			}
			dict[vuln.ID()] = vuln
			trimCVE(cve)
		}
	}
	return nil
}

func convertSummary(item *schema.NVDCVEFeedJSON10DefCVEItem) string {
	if item == nil || item.CVE == nil || item.CVE.Description == nil {
		return ""
	}
	for _, desc := range item.CVE.Description.DescriptionData {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func convertMetadata(item *schema.NVDCVEFeedJSON10DefCVEItem) *Metadata {
	if item == nil {
		return nil
	}
	metadata := &Metadata{
		PublishedDateTime:    item.PublishedDate,
		LastModifiedDateTime: item.LastModifiedDate,
	}
	if impact := item.Impact; impact != nil {
		if impact.BaseMetricV2 != nil && impact.BaseMetricV2.CVSSV2 != nil {
			metadata.CVSSv2 = MetadataCVSSv2{
				Vectors:             item.Impact.BaseMetricV2.CVSSV2.VectorString,
				Score:               item.Impact.BaseMetricV2.CVSSV2.BaseScore,
				ExploitabilityScore: item.Impact.BaseMetricV2.ExploitabilityScore,
				ImpactScore:         item.Impact.BaseMetricV2.ImpactScore,
			}
		}
		if impact.BaseMetricV3 != nil && impact.BaseMetricV3.CVSSV3 != nil {
			metadata.CVSSv3 = MetadataCVSSv3{
				Vectors:             item.Impact.BaseMetricV3.CVSSV3.VectorString,
				Score:               item.Impact.BaseMetricV3.CVSSV3.BaseScore,
				ExploitabilityScore: item.Impact.BaseMetricV3.ExploitabilityScore,
				ImpactScore:         item.Impact.BaseMetricV3.ImpactScore,
			}
		}
	}
	return metadata
}
