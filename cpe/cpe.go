package cpe

import (
	"fmt"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"time"
)

func getVulnsForComponent(layer string, potentialKeys []*wfn.Attributes, attributesToComponents map[wfn.Attributes]*component.Component) []database.FeatureVersion {
	featureMap := make(map[wfn.Attributes][]database.Vulnerability)

	t := time.Now()
	for _, vuln := range vulns {
		matches := vuln.Match(potentialKeys, false)
		for _, m := range matches {
			component := attributesToComponents[*m]
			generalizedAttr := wfn.Attributes{
				Product: component.Name,
				Version: component.Version,
			}
			attributesToComponents[generalizedAttr] = component
			featureMap[generalizedAttr] = append(featureMap[generalizedAttr], *vuln.Vulnerability())
			break
		}
	}
	fmt.Printf("Evaluation time: %0.4f\n", time.Since(t).Seconds())
	features := make([]database.FeatureVersion, 0, len(featureMap))
	for key, vulns := range featureMap {
		component := attributesToComponents[key]
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

func getAttributes(c *component.Component) []*wfn.Attributes {
	// TODO: Add any common logic up here.
	switch c.SourceType {
	case component.JavaSourceType:
		return getVersionsForJava(c)
	}
	return nil
}

func CheckForVulnerabilities(layer string, components []*component.Component) []database.FeatureVersion {
	possibleCPEsMap := make(map[wfn.Attributes]struct{})
	cpesToComponents := make(map[wfn.Attributes]*component.Component)
	var possibleCPEs []*wfn.Attributes
	for _, c := range components {
		attributes := getAttributes(c)
		for _, k := range attributes {
			if _, ok := possibleCPEsMap[*k]; ok {
				continue
			}
			possibleCPEsMap[*k] = struct{}{}
			cpesToComponents[*k] = c
			possibleCPEs = append(possibleCPEs, k)
		}
	}
	return getVulnsForComponent(layer, possibleCPEs, cpesToComponents)
}
