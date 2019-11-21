package common

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	numRegex = regexp.MustCompile(`[0-9].*$`)
)

func GenerateVersionKeys(c *component.Component) set.StringSet {
	return set.NewStringSet(c.Version, strings.ReplaceAll(c.Version, ".", `\.`))
}

func GenerateNameKeys(c *component.Component) set.StringSet {
	componentName := c.Name
	if componentName == "" {
		return set.NewStringSet()
	}
	return set.NewStringSet(
		componentName,
		strings.ReplaceAll(componentName, "_", "-"),
		strings.ReplaceAll(componentName, "-", "_"),
	)
}

func AddMutatedNameKeys(c *component.Component, nameSet set.StringSet) {
	base := numRegex.ReplaceAllString(c.Name, "")
	nameSet.Add(strings.TrimRight(base, "-_"))
	for name := range nameSet {
		if idx := strings.Index(name, "-"); idx != -1 {
			nameSet.Add(name[:idx])
		}
	}
}

func GenerateAttributesFromSets(vendor, name, version set.StringSet, targetSW string) []*wfn.Attributes {
	if vendor.Cardinality() == 0 {
		vendor.Add("")
	}
	attributes := make([]*wfn.Attributes, 0, vendor.Cardinality()*name.Cardinality()*version.Cardinality())
	for vendor := range vendor {
		for name := range name {
			for version := range version {
				attributes = append(attributes, &wfn.Attributes{
					Vendor:   strings.ToLower(vendor),
					Product:  strings.ToLower(name),
					Version:  strings.ToLower(version),
					TargetSW: targetSW,
				})
			}
		}
	}
	return attributes
}
