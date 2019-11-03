package cpe

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
)

var (
	vulns = make(map[productVersionPair][]*Vuln)
)

type productVersionPair struct {
	product, version string
}

type Vuln struct {
	cvefeed.Vuln
	Item *schema.NVDCVEFeedJSON10DefCVEItem
}

// ParseJSON parses JSON dictionary from NVD vulnerability feed
func parseJSON(reader io.ReadCloser) ([]*Vuln, error) {
	defer reader.Close()

	var feed schema.NVDCVEFeedJSON10
	if err := json.NewDecoder(reader).Decode(&feed); err != nil {
		return nil, err
	}

	vulns := make([]*Vuln, 0, len(feed.CVEItems))
	for _, cve := range feed.CVEItems {
		if cve != nil && cve.Configurations != nil {
			vulns = append(vulns, &Vuln{
				Vuln: nvd.ToVuln(cve),
				Item: cve,
			})
		}
	}
	return vulns, nil
}

type Matcher interface {
	Matches(s string) *database.Vulnerability
}

func handleJSONFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	fileVulns, err := parseJSON(f)
	if err != nil {
		panic(err)
	}
	filteredVulns := fileVulns[:0]
	for _, f := range fileVulns {
		var app bool
		for _, attr := range f.Config() {
			app = attr.Part == "a" || app
		}
		if app {
			for _, attr := vulns[f.]


			filteredVulns = append(filteredVulns, f)
		}
	}



	vulns = append(vulns, filteredVulns...)
}

func init() {
	definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR")
	if definitionsDir == "" {
		return
	}

	extractedPath := filepath.Join(definitionsDir, "cve")
	files, err := ioutil.ReadDir(extractedPath)
	if err != nil {
		log.Error(err)
		return
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		handleJSONFile(filepath.Join(extractedPath, f.Name()))
	}
}

func (v *Vuln) Summary() string {
	for _, desc := range v.Item.CVE.Description.DescriptionData {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

type Metadata struct {
	PublishedDateTime    string
	LastModifiedDateTime string
	CVSSv2               MetadataCVSSv2
	CVSSv3               MetadataCVSSv3
}

type MetadataCVSSv2 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

type MetadataCVSSv3 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

func (v *Vuln) Metadata() *Metadata {
	metadata := &Metadata{
		PublishedDateTime:    v.Item.PublishedDate,
		LastModifiedDateTime: v.Item.LastModifiedDate,
	}
	if impact := v.Item.Impact; impact != nil {
		if impact.BaseMetricV2 != nil && impact.BaseMetricV2.CVSSV2 != nil {
			metadata.CVSSv2 = MetadataCVSSv2{
				Vectors:             v.Item.Impact.BaseMetricV2.CVSSV2.VectorString,
				Score:               v.Item.Impact.BaseMetricV2.CVSSV2.BaseScore,
				ExploitabilityScore: v.Item.Impact.BaseMetricV2.ExploitabilityScore,
				ImpactScore:         v.Item.Impact.BaseMetricV2.ImpactScore,
			}
		}
		if impact.BaseMetricV3 != nil && impact.BaseMetricV3.CVSSV3 != nil {
			metadata.CVSSv3 = MetadataCVSSv3{
				Vectors:             v.Item.Impact.BaseMetricV3.CVSSV3.VectorString,
				Score:               v.Item.Impact.BaseMetricV3.CVSSV3.BaseScore,
				ExploitabilityScore: v.Item.Impact.BaseMetricV3.ExploitabilityScore,
				ImpactScore:         v.Item.Impact.BaseMetricV3.ImpactScore,
			}
		}
	}
	return metadata
}

func (v *Vuln) Vulnerability() *database.Vulnerability {
	return &database.Vulnerability{
		Name:        v.ID(),
		Description: v.Summary(),
		Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.ID()),
		Metadata: map[string]interface{}{
			"NVD": v.Metadata(),
		},
	}
}
