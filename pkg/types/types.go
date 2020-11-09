package types

import (
	"fmt"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/cvss2"
	"github.com/facebookincubator/nvdtools/cvss3"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/math"
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

func ConvertMetadataFromK8s(cve *validation.CVESchema) (*Metadata, error) {
	m := Metadata{}
	if nvd := cve.CVSS.NVD; nvd != nil {
		if nvd.VectorV2 != "" && nvd.ScoreV2 > 0 {
			v, err := cvss2.VectorFromString(nvd.VectorV2)
			if err != nil {
				return nil, err
			}
			m.CVSSv2.Score = nvd.ScoreV2
			m.CVSSv2.Vectors = nvd.VectorV2
			m.CVSSv2.ExploitabilityScore = math.RoundTo1Decimal(v.ExploitabilityScore())
			m.CVSSv2.ImpactScore = math.RoundTo1Decimal(v.ImpactScore(false))
		}
		if nvd.VectorV3 != "" && nvd.ScoreV3 > 0 {
			v, err := cvss3.VectorFromString(nvd.VectorV2)
			if err != nil {
				return nil, err
			}
			m.CVSSv3.Score = nvd.ScoreV3
			m.CVSSv3.Vectors = nvd.VectorV3
			m.CVSSv3.ExploitabilityScore = math.RoundTo1Decimal(v.ExploitabilityScore())
			m.CVSSv3.ImpactScore = math.RoundTo1Decimal(v.ImpactScore())
		}
	}
	if k8s := cve.CVSS.Kubernetes; k8s != nil {
		if k8s.VectorV3 != "" && k8s.ScoreV3 > 0 {
			v, err := cvss3.VectorFromString(k8s.VectorV3)
			if err != nil {
				return nil, err
			}
			m.CVSSv3.Score = k8s.ScoreV3
			m.CVSSv3.Vectors = k8s.VectorV3
			m.CVSSv3.ExploitabilityScore = math.RoundTo1Decimal(v.ExploitabilityScore())
			m.CVSSv3.ImpactScore = math.RoundTo1Decimal(v.ImpactScore())
		}
	}

	return &m, nil
}
