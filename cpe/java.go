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
	for _, k := range versionSet.AsSlice() {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	nameSet := make(map[string]struct{})
	nameSet[java.Name] = struct{}{}
	nameSet[strings.ReplaceAll(java.Name, "_", "-")] = struct{}{}
	nameSet[strings.ReplaceAll(java.Name, "-", "_")] = struct{}{}
	nameSet[numRegex.ReplaceAllString(java.Name, "")] = struct{}{}

	for name := range nameSet {
		if idx := strings.Index(name, "-"); idx != -1 {
			nameSet[name[:idx]] = struct{}{}
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
		for _, version := range versionSet.AsSlice() {
			cpeKeys = append(cpeKeys, cpeKey{vendor: vendor, pkg: name, version: version})
		}
	}
	return cpeKeys
}
