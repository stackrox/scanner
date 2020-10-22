package cpe

import (
	"sort"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/cpe/attributes/dotnetcoreruntime"
	"github.com/stackrox/scanner/cpe/attributes/java"
	"github.com/stackrox/scanner/cpe/attributes/node"
	"github.com/stackrox/scanner/cpe/attributes/python"
	"github.com/stackrox/scanner/cpe/attributes/ruby"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
)

var attributeGetter = map[component.SourceType]func(c *component.Component) []*wfn.Attributes{
	component.PythonSourceType:            python.GetPythonAttributes,
	component.JavaSourceType:              java.GetJavaAttributes,
	component.GemSourceType:               ruby.GetRubyAttributes,
	component.NPMSourceType:               node.GetNodeAttributes,
	component.DotNetCoreRuntimeSourceType: dotnetcoreruntime.GetDotNetCoreRuntimeAttributes,
}

type nameVersion struct {
	name, version string
}

func getNameVersionFromCPE(attr *wfn.Attributes, versionOverride string) nameVersion {
	tmpName := strings.ReplaceAll(attr.Product, `\-`, "-")
	return nameVersion{
		name:    strings.ReplaceAll(tmpName, `\.`, "."),
		version: stringutils.OrDefault(versionOverride, strings.ReplaceAll(attr.Version, `\.`, ".")),
	}
}

func getFeaturesFromMatchResults(layer string, matchResults []match.Result) []database.FeatureVersion {
	if len(matchResults) == 0 {
		return nil
	}

	featuresMap := make(map[nameVersion]*database.FeatureVersion)
	featuresToVulns := make(map[nameVersion]set.StringSet)
	for _, m := range matchResults {
		if m.CPE.Attributes == nil {
			continue
		}
		cpe := m.CPE
		nameVersion := getNameVersionFromCPE(cpe.Attributes, m.VersionOverride)

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
					Name:       nameVersion.name,
					SourceType: m.Component.SourceType.String(),
					Location:   m.Component.Location,
				},
				Version: nameVersion.version,
				AddedBy: database.Layer{
					Name: layer,
				},
			}
			featuresMap[nameVersion] = feature
		}
		m.Vuln.FixedBy = cpe.FixedIn
		feature.AffectedBy = append(feature.AffectedBy, *m.Vuln)
	}
	features := make([]database.FeatureVersion, 0, len(featuresMap))
	for _, feature := range featuresMap {
		features = append(features, *feature)
	}
	return features
}

func escapeDash(s string) string {
	return strings.ReplaceAll(s, "-", `\-`)
}

func getAttributes(c *component.Component) []*wfn.Attributes {
	getAttributes := attributeGetter[c.SourceType]
	if getAttributes == nil {
		log.Errorf("No attribute getter available for %q", c.SourceType.String())
		return nil
	}
	attrs := getAttributes(c)
	for _, a := range attrs {
		a.Product = escapeDash(a.Product)
		a.Vendor = escapeDash(a.Vendor)
	}
	return attrs
}

func compareAttributes(c1, c2 wfn.AttributesWithFixedIn) int {
	if cmp := strings.Compare(c1.Vendor, c2.Vendor); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(c1.Product, c2.Product); cmp != 0 {
		return cmp
	}
	return strings.Compare(c1.Version, c2.Version)
}

// getMostSpecificCPE deterministically returns the CPE that is the most specific
// from the set of matches. This function requires that len(cpes) > 0
func getMostSpecificCPE(cpes []wfn.AttributesWithFixedIn) wfn.AttributesWithFixedIn {
	mostSpecificCPE := cpes[0]
	for _, cpe := range cpes[1:] {
		if compareAttributes(cpe, mostSpecificCPE) > 0 {
			mostSpecificCPE = cpe
		}
	}
	return mostSpecificCPE
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	cache := nvdtoolscache.Singleton()
	var matchResults []match.Result

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})
	for _, c := range components {
		attributes := getAttributes(c)
		products := set.NewStringSet()
		for _, a := range attributes {
			if a.Product != "" {
				products.Add(a.Product)
			}
		}

		// DotNetCoreRuntime CVEs in NVD are attributed to Major.Minor version
		// instead of the full Major.Minor.Patch version.
		// Because of this, we want to make sure to return the full version
		// for this source type.
		var versionOverride string
		if c.SourceType == component.DotNetCoreRuntimeSourceType {
			versionOverride = c.Version
		}

		vulns, err := cache.GetVulnsForProducts(products.AsSlice())
		if err != nil {
			log.Errorf("error getting vulns for products: %v", err)
			continue
		}
		for _, v := range vulns {
			if matchesWithFixed := v.MatchWithFixedIn(attributes, false); len(matchesWithFixed) > 0 {
				result := match.Result{
					CVE:             v,
					CPE:             getMostSpecificCPE(matchesWithFixed),
					VersionOverride: versionOverride,
					Component:       c,
					Vuln:            nvdtoolscache.NewVulnerability(v.(*nvd.Vuln).CVEItem),
				}

				validator, ok := validation.Validators[c.SourceType]
				if !ok {
					log.Errorf("could not find validator for source type: %q", c.SourceType)
					continue
				}
				if !validator.ValidateResult(result) {
					continue
				}
				matchResults = append(matchResults, result)
			}
		}
	}

	return getFeaturesFromMatchResults(layer, matchResults)
}
