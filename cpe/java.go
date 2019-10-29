package cpe

import (
	"regexp"
	"strings"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	extensionRegex = regexp.MustCompile(`\.(RELEASE|GA|SEC.*)$`)
	numRegex       = regexp.MustCompile(`[0-9].*$`)
)

func getVersionsForJava(component *component.Component) []cpeKey {
	java := component.JavaPkgMetadata

	versionSet := set.NewStringSet()
	if java.ImplementationVersion != "" {
		versionSet.Add(java.ImplementationVersion)
	}
	if java.MavenVersion != "" {
		versionSet.Add(java.MavenVersion)
	}
	if java.SpecificationVersion != "" {
		versionSet.Add(java.MavenVersion)
	}
	for k := range versionSet {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	nameSet := set.NewStringSet(
		java.Name,
		strings.ReplaceAll(java.Name, "_", "-"),
		strings.ReplaceAll(java.Name, "-", "_"),
		numRegex.ReplaceAllString(java.Name, ""),
	)

	for name := range nameSet {
		if idx := strings.Index(name, "-"); idx != -1 {
			nameSet.Add(name[:idx])
		}
	}

	var vendor string
	originSpl := strings.Split(java.Origin, ".")
	// Typically this is org.vendor.product
	if len(originSpl) >= 2 {
		vendor = originSpl[1]
	}

	var cpeKeys []cpeKey
	for name := range nameSet {
		for version := range versionSet {
			cpeKeys = append(cpeKeys, cpeKey{vendor: vendor, pkg: name, version: version})
		}
	}
	return cpeKeys
}
