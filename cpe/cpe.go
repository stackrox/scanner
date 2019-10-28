package cpe

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

type cpeKey struct {
	vendor, pkg, version string
}

func getVulnsForComponent(layer string, potentialKeys []cpeKey) []database.FeatureVersion {
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
	possibleCPEsMap := make(map[cpeKey]struct{})
	var possibleCPEs []cpeKey
	for _, c := range components {
		keys := getVersionsForJava(c)
		for _, k := range keys {
			if _, ok := possibleCPEsMap[k]; ok {
				continue
			}
			possibleCPEsMap[k] = struct{}{}
			possibleCPEs = append(possibleCPEs, k)
		}
	}
	return getVulnsForComponent(layer, possibleCPEs)
}
