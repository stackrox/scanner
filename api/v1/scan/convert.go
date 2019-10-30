package scan

import (
	"encoding/json"

	apiV1 "github.com/stackrox/scanner/api/v1"
	v1 "github.com/stackrox/scanner/generated/api/v1"
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
