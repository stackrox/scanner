package java

import (
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/pkg/component"

	"regexp"
	"strings"
)

var (
	extensionRegex = regexp.MustCompile(`\.(RELEASE|GA|SEC.*)$`)
)

func init() {
	cpe.Register(component.JavaSourceType, getVersionsForJava)
}

func getVersionsForJava(component *component.Component) (vendors, pkgs, versions set.StringSet) {
	java := component.JavaPkgMetadata
	if java == nil {
		return nil, nil, nil
	}

	versionSet := set.NewStringSet()
	versionSet.AddMatching(func(s string) bool {
		return s != ""
	}, java.ImplementationVersion, java.MavenVersion, java.SpecificationVersion)
	for k := range versionSet {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	vendor := set.NewStringSet()
	originSpl := strings.Split(java.Origin, ".")
	// Typically this is org.vendor.product
	if len(originSpl) >= 2 {
		vendor.Add(originSpl[1])
	}
	return vendor, set.NewStringSet(), versionSet
}
