package cpe

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

func generateNameKeys(componentName string, hasVendor bool) set.StringSet {
	if componentName == "" {
		return set.NewStringSet()
	}
	nameSet := set.NewStringSet(
		componentName,
		strings.ReplaceAll(componentName, "_", "-"),
		strings.ReplaceAll(componentName, "-", "_"),
	)

	if hasVendor {
		nameSet.Add(numRegex.ReplaceAllString(componentName, ""))
		for name := range nameSet {
			if idx := strings.Index(name, "-"); idx != -1 {
				nameSet.Add(name[:idx])
			}
		}
	}

	return nameSet
}

func generateVersionKeys(c *component.Component) set.StringSet {
	return set.NewStringSet(c.Version, strings.ReplaceAll(c.Version, ".", `\.`))
}

func normalVersionKeys(v string) string {
	return strings.ReplaceAll(v, `\.`, ".")
}

type nameVersion struct {
	name, version string
}

func getFeaturesFromMatchResults(layer string, matchResults []cvefeed.MatchResult, cveToVulns map[string]*Vuln) []database.FeatureVersion {
	if len(matchResults) == 0 {
		return nil
	}

	featuresMap := make(map[nameVersion]*database.FeatureVersion)
	featuresToVulns := make(map[nameVersion]set.StringSet)
	for _, m := range matchResults {
		cve, ok := cveToVulns[m.CVE.ID()]
		if !ok {
			log.Errorf("CVE %q not found in CVE map", m.CVE.ID())
			continue
		}
		if len(m.CPEs) == 0 {
			log.Errorf("Found 0 CPEs in match with CVE %q", m.CVE.ID())
			continue
		}
		for _, cpe := range m.CPEs {
			name, version := cpe.Product, normalVersionKeys(cpe.Version)
			nameVersion := nameVersion{
				name:    name,
				version: version,
			}

			vulnSet, ok := featuresToVulns[nameVersion]
			if !ok {
				vulnSet = set.NewStringSet()
				featuresToVulns[nameVersion] = vulnSet
			}
			if !vulnSet.Add(m.CVE.ID()) {
				continue
			}

			feature, ok := featuresMap[nameVersion]
			if !ok {
				feature = &database.FeatureVersion{
					Feature: database.Feature{
						Name: name,
					},
					Version: version,
					AddedBy: database.Layer{
						Name: layer,
					},
				}
				featuresMap[nameVersion] = feature
			}
			feature.AffectedBy = append(feature.AffectedBy, *cve.Vulnerability())
		}
	}
	features := make([]database.FeatureVersion, 0, len(featuresMap))
	for _, feature := range featuresMap {
		features = append(features, *feature)
	}
	return features
}

func getAttributes(c *component.Component) []*wfn.Attributes {
	vendorSet := set.NewStringSet()
	nameSet := set.NewStringSet()
	versionSet := generateVersionKeys(c)

	if generator, ok := generators[c.SourceType]; ok {
		generator(c, vendorSet, nameSet, versionSet)
	}

	nameSet = nameSet.Union(generateNameKeys(c.Name, vendorSet.Cardinality() != 0))
	if vendorSet.Cardinality() == 0 {
		vendorSet.Add("")
	}
	attributes := make([]*wfn.Attributes, 0, vendorSet.Cardinality()*nameSet.Cardinality()*versionSet.Cardinality())
	for vendor := range vendorSet {
		for name := range nameSet {
			for version := range versionSet {
				var tgtSW string
				if c.SourceType == component.NPMSourceType {
					tgtSW = `node\.js`
				}
				attributes = append(attributes, &wfn.Attributes{
					Vendor:   strings.ToLower(vendor),
					Product:  strings.ToLower(name),
					Version:  strings.ToLower(version),
					TargetSW: tgtSW,
				})
			}
		}
	}
	return attributes
}

func filterMatchResultsByTargetSoftware(matchResults []cvefeed.MatchResult) []cvefeed.MatchResult {
	filteredResults := make([]cvefeed.MatchResult, 0, len(matchResults))
	for _, f := range matchResults {
		// If the CPE has a language specified, then ensure that the language is ensured in the result CPE
		var tgt string
		for _, matchedAttribute := range f.CPEs {
			if tgt = matchedAttribute.TargetSW; tgt != "" {
				break
			}
		}
		for _, cveCPE := range f.CVE.Config() {
			if cveCPE.TargetSW == tgt {
				filteredResults = append(filteredResults, f)
			}
		}
	}
	return filteredResults
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	var matchResults []cvefeed.MatchResult
	for _, c := range components {
		attributes := getAttributes(c)
		matchResults = append(matchResults, cache.Get(attributes)...)
	}
	matchResults = filterMatchResultsByTargetSoftware(matchResults)

	return getFeaturesFromMatchResults(layer, matchResults, cveMap)
}
