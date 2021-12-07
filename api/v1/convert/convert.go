package convert

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/nvd"
	"github.com/stackrox/scanner/pkg/types"
)

// Metadata converts from types.Metadata to v1.Metadata
func Metadata(m *types.Metadata) *v1.Metadata {
	if m.IsNilOrEmpty() {
		return nil
	}
	metadata := &v1.Metadata{
		PublishedDateTime:    m.PublishedDateTime,
		LastModifiedDateTime: m.LastModifiedDateTime,
	}
	if m.CVSSv2.Vectors != "" {
		cvssV2 := m.CVSSv2
		metadata.CvssV2 = &v1.CVSSMetadata{
			Vector:              cvssV2.Vectors,
			Score:               float32(cvssV2.Score),
			ExploitabilityScore: float32(cvssV2.ExploitabilityScore),
			ImpactScore:         float32(cvssV2.ImpactScore),
		}
	}
	if m.CVSSv3.Vectors != "" {
		cvssV3 := m.CVSSv3
		metadata.CvssV3 = &v1.CVSSMetadata{
			Vector:              cvssV3.Vectors,
			Score:               float32(cvssV3.Score),
			ExploitabilityScore: float32(cvssV3.ExploitabilityScore),
			ImpactScore:         float32(cvssV3.ImpactScore),
		}
	}

	return metadata
}

// MetadataMap converts the internal map[string]interface{} into the API metadata
func MetadataMap(metadataMap map[string]interface{}) (*v1.Metadata, error) {
	var metadataBytes interface{}
	if metadata, exists := metadataMap["Red Hat"]; exists {
		metadataBytes = metadata
	} else if metadata, exists := metadataMap["NVD"]; exists {
		metadataBytes = metadata
	}

	d, err := json.Marshal(&metadataBytes)
	if err != nil {
		return nil, err
	}

	var m types.Metadata
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, err
	}
	return Metadata(&m), err
}

// NVDVulns converts the NVD vuln structure into the API Vulnerability
func NVDVulns(nvdVulns []*nvdtoolscache.NVDCVEItemWithFixedIn) ([]*v1.Vulnerability, error) {
	vulns := make([]*v1.Vulnerability, 0, len(nvdVulns))
	for _, vuln := range nvdVulns {
		m := types.ConvertNVDMetadata(vuln.NVDCVEFeedJSON10DefCVEItem)
		if m.IsNilOrEmpty() {
			logrus.Warnf("Metadata empty or nil for %v; skipping...", vuln.CVE.CVEDataMeta.ID)
			continue
		}
		vulns = append(vulns, &v1.Vulnerability{
			Name:        vuln.CVE.CVEDataMeta.ID,
			Description: types.ConvertNVDSummary(vuln.NVDCVEFeedJSON10DefCVEItem),
			Link:        nvd.Link(vuln.CVE.CVEDataMeta.ID),
			MetadataV2:  Metadata(m),
			FixedBy:     vuln.FixedIn,
		})
	}

	return vulns, nil
}
