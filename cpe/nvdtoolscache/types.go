package nvdtoolscache

import (
	"fmt"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stackrox/scanner/database"
)

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

func NewVulnerability(cveitem *schema.NVDCVEFeedJSON10DefCVEItem) *database.Vulnerability {
	return &database.Vulnerability{
		Name:        cveitem.CVE.CVEDataMeta.ID,
		Description: convertSummary(cveitem),
		Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveitem.CVE.CVEDataMeta.ID),
		Metadata: map[string]interface{}{
			"NVD": convertMetadata(cveitem),
		},
	}
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
