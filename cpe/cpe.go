package cpe

import (
	"regexp"
	"strings"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

type cpeKey struct {
	vendor, pkg, version string
}

func getVulnsForComponent(layer string, potentialKeys []cpeKey, cpeToComponentMap map[cpeKey]*component.Component) []database.FeatureVersion {
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
		component := cpeToComponentMap[key]
		features = append(features, database.FeatureVersion{
			Feature: database.Feature{
				Name: component.Name,
			},
			Version:    component.Version,
			AffectedBy: vulns,
			AddedBy: database.Layer{
				Name: layer,
			},
		})
	}
	return features
}

func generateNameKeys(c *component.Component) set.StringSet {
	nameSet := set.NewStringSet(
		c.Name,
		strings.ReplaceAll(c.Name, "_", "-"),
		strings.ReplaceAll(c.Name, "-", "_"),
		numRegex.ReplaceAllString(c.Name, ""),
	)
	for name := range nameSet {
		if idx := strings.Index(name, "-"); idx != -1 {
			nameSet.Add(name[:idx])
		}
	}
	return nameSet
}

func generateVersionKeys(c *component.Component) set.StringSet {
	return set.NewStringSet(c.Version)
}

func getKeys(c *component.Component) []cpeKey {
	vendorSet := set.NewStringSet()
	nameSet := generateNameKeys(c)
	versionSet := generateVersionKeys(c)

	if generator, ok := generators[c.SourceType]; ok {
		languageVendorSet, languageNameSet, languageVersionSet := generator(c)
		vendorSet = vendorSet.Union(languageVendorSet)
		nameSet = nameSet.Union(languageNameSet)
		versionSet = versionSet.Union(languageVersionSet)
	}

	cpeKeys := make([]cpeKey, 0, vendorSet.Cardinality()*nameSet.Cardinality()*versionSet.Cardinality())
	for _, vendor := range vendorSet.AsSlice() {
		for _, name := range nameSet.AsSlice() {
			for _, version := range versionSet.AsSlice() {
				cpeKeys = append(cpeKeys, cpeKey{
					vendor:  vendor,
					pkg:     name,
					version: version,
				})
			}
		}
	}
	return cpeKeys
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	possibleCPEsMap := make(map[cpeKey]struct{})
	cpesToComponents := make(map[cpeKey]*component.Component)
	var possibleCPEs []cpeKey
	for _, c := range components {
		keys := getKeys(c)
		for _, k := range keys {
			if _, ok := possibleCPEsMap[k]; ok {
				continue
			}
			possibleCPEsMap[k] = struct{}{}
			cpesToComponents[k] = c
			possibleCPEs = append(possibleCPEs, k)
		}
	}
	return getVulnsForComponent(layer, possibleCPEs, cpesToComponents)
}
