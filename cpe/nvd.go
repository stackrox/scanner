package cpe

import (
	"encoding/json"
	"fmt"
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
	cache  *cvefeed.Cache
	cveMap = make(map[string]*Vuln)
)

type Vuln struct {
	Item *schema.NVDCVEFeedJSON10DefCVEItem
}

func (v *Vuln) ID() string {
	if v.Item != nil && v.Item.CVE != nil && v.Item.CVE.CVEDataMeta != nil {
		return v.Item.CVE.CVEDataMeta.ID
	}
	return ""
}

type Matcher interface {
	Matches(s string) *database.Vulnerability
}

func handleJSONFile(dict cvefeed.Dictionary, path string) error {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var feed schema.NVDCVEFeedJSON10
	if err := json.NewDecoder(f).Decode(&feed); err != nil {
		return err
	}

	for _, cve := range feed.CVEItems {
		if cve != nil && cve.Configurations != nil {
			vuln := nvd.ToVuln(cve)
			var isAppCPE bool
			for _, a := range vuln.Config() {
				isAppCPE = a.Part == "a" || isAppCPE
			}
			if isAppCPE {
				cveMap[vuln.ID()] = &Vuln{
					Item: cve,
				}
				dict[vuln.ID()] = vuln
			}
		}
	}
	return nil
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

	dict := make(cvefeed.Dictionary)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		if err := handleJSONFile(dict, filepath.Join(extractedPath, f.Name())); err != nil {
			panic(err)
		}
	}
	log.Infof("Total vulns: %d", len(cveMap))

	cache = cvefeed.NewCache(dict).SetMaxSize(-1).SetRequireVersion(false)
	cache.Idx = cvefeed.NewIndex(dict)

	// After this is built, nil out the configurations of the nodes as they are not relevant and can be GC'd
	for _, v := range cveMap {
		v.Item.Configurations = nil
	}
}

func (v *Vuln) Summary() string {
	if v.Item == nil || v.Item.CVE == nil || v.Item.CVE.Description == nil {
		return ""
	}
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
	if v.Item == nil {
		return nil
	}
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
