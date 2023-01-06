package features

import (
	log "github.com/sirupsen/logrus"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/convert"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
)

// ConvertFeatures converts api Features into v1 (proto) Feature pointers.
func ConvertFeatures(apiFeatures []apiV1.Feature) []*v1.Feature {
	features := make([]*v1.Feature, 0, len(apiFeatures))
	for _, a := range apiFeatures {
		vulns := convertVulnerabilities(a.Vulnerabilities)

		features = append(features, &v1.Feature{
			Name:                a.Name,
			Version:             a.Version,
			FeatureType:         a.VersionFormat,
			AddedByLayer:        a.AddedBy,
			Location:            a.Location,
			Vulnerabilities:     vulns,
			FixedBy:             a.FixedBy,
			ProvidedExecutables: a.Executables,
		})
	}
	return features
}

func convertVulnerabilities(apiVulns []apiV1.Vulnerability) []*v1.Vulnerability {
	vulns := make([]*v1.Vulnerability, 0, len(apiVulns))
	for _, v := range apiVulns {
		metadata, err := convert.MetadataMap(v.Metadata)
		if err != nil {
			log.Errorf("error converting metadata map: %v", err)
			continue
		}
		if metadata == nil {
			log.Warnf("metadata is nil for %s; skipping...", v.Name)
			continue
		}

		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.Name,
			Description: v.Description,
			Link:        v.Link,
			MetadataV2:  metadata,
			FixedBy:     v.FixedBy,
			Severity:    v.Severity,
		})
	}
	return vulns
}
