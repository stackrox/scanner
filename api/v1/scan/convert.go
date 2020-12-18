package scan

import (
	"encoding/json"
	"strings"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/stringutils"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/types"
)

var (
	sourceTypeToProtoMap = func() map[component.SourceType]v1.SourceType {
		numComponentSourceTypes := int(component.SentinelEndSourceType) - int(component.UnsetSourceType)
		if numComponentSourceTypes != len(v1.SourceType_value) {
			panic("Number of source types in proto and Go are not equal")
		}

		m := make(map[component.SourceType]v1.SourceType, numComponentSourceTypes)
		for name, val := range v1.SourceType_value {
			normalizedName := strings.ToLower(strings.TrimSuffix(name, "_SOURCE_TYPE"))
			for sourceType := component.UnsetSourceType; sourceType < component.SentinelEndSourceType; sourceType++ {
				if strings.HasPrefix(strings.ToLower(sourceType.String()), normalizedName) {
					m[sourceType] = v1.SourceType(val)
				}
			}
		}
		if len(m) != numComponentSourceTypes {
			panic("Mismatch in source types in proto and code")
		}
		return m
	}()
)

func convertVulnerabilities(apiVulns []apiV1.Vulnerability) ([]*v1.Vulnerability, error) {
	vulns := make([]*v1.Vulnerability, 0, len(apiVulns))
	for _, v := range apiVulns {
		var metadataBytes interface{}
		if metadata, exists := v.Metadata["NVD"]; exists {
			metadataBytes = metadata
		} else if metadata, exists := v.Metadata["Red Hat"]; exists {
			metadataBytes = metadata
		}

		d, err := json.Marshal(&metadataBytes)
		if err != nil {
			continue
		}

		var m types.Metadata
		if json.Unmarshal(d, &m) != nil {
			continue
		}

		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.Name,
			Description: v.Description,
			Link:        v.Link,
			MetadataV2:  convertMetadata(&m),
			FixedBy:     v.FixedBy,
		})
	}
	return vulns, nil
}

func convertFeatures(apiFeatures []apiV1.Feature) ([]*v1.Feature, error) {
	features := make([]*v1.Feature, 0, len(apiFeatures))
	for _, a := range apiFeatures {
		vulns, err := convertVulnerabilities(a.Vulnerabilities)
		if err != nil {
			return nil, err
		}

		features = append(features, &v1.Feature{
			Name:            a.Name,
			Version:         a.Version,
			Vulnerabilities: vulns,
			FeatureType:     a.VersionFormat,
			AddedByLayer:    a.AddedBy,
			Location:        a.Location,
		})
	}
	return features, nil
}

func convertComponents(layersToComponents []*component.LayerToComponents) map[string]*v1.LanguageLevelComponents {
	converted := make(map[string]*v1.LanguageLevelComponents, len(layersToComponents))
	for _, layerToComponents := range layersToComponents {
		converted[layerToComponents.Layer] = convertComponentsSlice(layerToComponents.Components)
	}
	return converted
}

func convertComponentsSlice(components []*component.Component) *v1.LanguageLevelComponents {
	converted := make([]*v1.LanguageLevelComponent, 0, len(components))
	for _, c := range components {
		converted = append(converted, convertComponent(c))
	}
	return &v1.LanguageLevelComponents{
		Components: converted,
	}
}

func convertComponent(c *component.Component) *v1.LanguageLevelComponent {
	return &v1.LanguageLevelComponent{
		SourceType: sourceTypeToProtoMap[c.SourceType],
		Name:       c.Name,
		Version:    c.Version,
		Location:   c.Location,
	}
}

func convertK8sVulnerabilities(version string, k8sVulns []*validation.CVESchema) ([]*v1.Vulnerability, error) {
	vulns := make([]*v1.Vulnerability, 0, len(k8sVulns))
	for _, v := range k8sVulns {
		m, err := types.ConvertMetadataFromK8s(v)
		if err != nil {
			log.Errorf("Unable to convert metadata for %s: %v", v.CVE, err)
			continue
		}

		link := stringutils.OrDefault(v.IssueURL, v.URL)
		fixedBy, err := getFixedBy(version, v)
		if err != nil {
			log.Errorf("Unable to get FixedBy for %s: %v", v.CVE, err)
			continue
		}
		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.CVE,
			Description: v.Description,
			Link:        link,
			MetadataV2:  convertMetadata(m),
			FixedBy:     fixedBy,
		})
	}
	return vulns, nil
}

func getFixedBy(vStr string, vuln *validation.CVESchema) (string, error) {
	v, err := version.NewVersion(vStr)
	if err != nil {
		return "", err
	}

	for _, affected := range vuln.Affected {
		constraint, err := version.NewConstraint(affected.Range)
		if err != nil {
			return "", err
		}
		if constraint.Check(v) {
			return affected.FixedBy, nil
		}
	}

	return "", nil
}

func convertNVDVulns(nvdVulns []*nvdtoolscache.NVDCVEItemWithFixedIn) ([]*v1.Vulnerability, error) {
	vulns := make([]*v1.Vulnerability, 0, len(nvdVulns))
	for _, vuln := range nvdVulns {
		m := types.ConvertNVDMetadata(vuln.NVDCVEFeedJSON10DefCVEItem)
		vulns = append(vulns, &v1.Vulnerability{
			Name:        vuln.CVE.CVEDataMeta.ID,
			Description: types.ConvertNVDSummary(vuln.NVDCVEFeedJSON10DefCVEItem),
			Link:        "https://nvd.nist.gov/vuln/detail/" + vuln.CVE.CVEDataMeta.ID,
			MetadataV2:  convertMetadata(m),
			FixedBy:     vuln.FixedIn,
		})
	}

	return vulns, nil
}

func convertMetadata(m *types.Metadata) *v1.Metadata {
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
