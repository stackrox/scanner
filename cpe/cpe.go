package cpe

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

type cpeKey struct {
	vendor, pkg, version string
}

func getVulnsForComponent(layer string, c *component.Component) []database.FeatureVersion {
	potentialKeys := getVersionsForJava(c)

	featureMap := make(map[cpeKey][]database.Vulnerability)
	for _, key := range potentialKeys {
		matchers := cpeMatcher[key.vendor][key.pkg]
		for _, matcher := range matchers {
			if vuln := matcher.Matches(key.version); vuln != nil {
				featureMap[key] = append(featureMap[key], *vuln)
			}
		}
	}

	features := make([]database.FeatureVersion, 0, len(featureMap))
	for key, vulns := range featureMap {
		features = append(features, database.FeatureVersion{
			Feature: database.Feature{
				Name: key.pkg,
			},
			Version:    key.version,
			AffectedBy: vulns,
			AddedBy: database.Layer{
				Name: layer,
			},
		})
	}
	return features
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	var features []database.FeatureVersion
	for _, c := range components {
		features = append(features, getVulnsForComponent(layer, c)...)
	}
	return features
}
