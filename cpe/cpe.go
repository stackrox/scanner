package cpe

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

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

type nameVersion struct {
	name, version string
}

func getVulnsForComponent(layer string, attributes []*wfn.Attributes) []database.FeatureVersion {
	matchResults := cache.Get(attributes)
	if len(matchResults) == 0 {
		return nil
	}

	vulnSet := set.NewStringSet()
	featuresMap := make(map[nameVersion][]database.Vulnerability)
	for _, m := range matchResults {
		if !vulnSet.Add(m.CVE.ID()) {
			continue
		}
		cpe := m.CPEs[0]
		cve, ok := cveMap[m.CVE.ID()]
		if !ok {
			log.Errorf("CVE %q not found in CVE map", m.CVE.ID())
			continue
		}
		nameVersionPair := nameVersion{name: cpe.Product, version: cpe.Version}
		featuresMap[nameVersionPair] = append(featuresMap[nameVersionPair], *cve.Vulnerability())
	}

	features := make([]database.FeatureVersion, 0, len(featuresMap))
	for pair, vulns := range featuresMap {
		features = append(features, database.FeatureVersion{
			Feature: database.Feature{
				Name: pair.name,
			},
			Version:    pair.version,
			AffectedBy: vulns,
			AddedBy: database.Layer{
				Name: layer,
			},
		})
	}
	return features
}

func getAttributes(c *component.Component) []*wfn.Attributes {
	vendorSet := set.NewStringSet()
	nameSet := generateNameKeys(c)
	versionSet := generateVersionKeys(c)

	if generator, ok := generators[c.SourceType]; ok {
		languageVendorSet, languageNameSet, languageVersionSet := generator(c)
		vendorSet = vendorSet.Union(languageVendorSet)
		nameSet = nameSet.Union(languageNameSet)
		versionSet = versionSet.Union(languageVersionSet)
	}

	if vendorSet.Cardinality() == 0 {
		vendorSet.Add("")
	}
	attributes := make([]*wfn.Attributes, 0, vendorSet.Cardinality()*nameSet.Cardinality()*versionSet.Cardinality())
	for _, vendor := range vendorSet.AsSlice() {
		for _, name := range nameSet.AsSlice() {
			for _, version := range versionSet.AsSlice() {
				attributes = append(attributes, &wfn.Attributes{
					Vendor:  vendor,
					Product: name,
					Version: version,
				})
			}
		}
	}
	return attributes
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	uniqueAttributes := make(map[wfn.Attributes]struct{})
	var allAttributes []*wfn.Attributes
	for _, c := range components {
		for _, a := range getAttributes(c) {
			if _, ok := uniqueAttributes[*a]; ok {
				continue
			}
			allAttributes = append(allAttributes, a)
			uniqueAttributes[*a] = struct{}{}
		}
	}

	return getVulnsForComponent(layer, allAttributes)
}
