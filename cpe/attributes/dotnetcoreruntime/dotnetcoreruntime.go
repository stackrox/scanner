package dotnetcoreruntime

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	// The CPE product names were derived via a search through the NVD CPE database for
	// .NET Core runtime-related products https://nvd.nist.gov/products/cpe/search
	// and observing the CPEs for known related CVEs.
	nameToCPEProducts = map[string][]string{
		"Microsoft.NETCore.App": {
			".net_core",
		},
		"Microsoft.AspNetCore.App": {
			"asp.net_core",
		},
	}
)

func GetDotNetCoreRuntimeAttributes(c *component.Component) []*wfn.Attributes {
	vendorSet := set.NewStringSet("microsoft")

	nameSet := set.NewStringSet()
	for _, name := range nameToCPEProducts[c.Name] {
		nameSet.AddAll(name, escapePeriod(name))
	}

	// The CPEs only seem to look at the major and minor versions of the semantic version.
	majorMinorVersion := c.Version[:strings.LastIndex(c.Version, ".")]
	versionSet := set.NewStringSet(majorMinorVersion, escapePeriod(majorMinorVersion))

	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}

func escapePeriod(str string) string {
	return strings.ReplaceAll(str, ".", `\.`)
}
