package scan

import (
	"encoding/json"
	"strings"

	apiV1 "github.com/stackrox/scanner/api/v1"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/component"
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
		metadataBytes, err := json.Marshal(v.Metadata)
		if err != nil {
			return nil, err
		}

		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.Name,
			Description: v.Description,
			Link:        v.Link,
			Metadata:    metadataBytes,
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
		})
	}
	return features, nil
}

func convertComponents(componentsMap map[string][]*component.Component) map[string]*v1.LanguageLevelComponents {
	converted := make(map[string]*v1.LanguageLevelComponents, len(componentsMap))
	for k, v := range componentsMap {
		converted[k] = convertComponentsSlice(v)
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
