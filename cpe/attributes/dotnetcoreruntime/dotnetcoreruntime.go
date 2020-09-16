package dotnetcoreruntime

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

var (
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

	names := nameToCPEProducts[c.Name]
	nameSet := set.NewStringSet(names...)
	for _, name := range names {
		nameSet.Add(escapePeriod(name))
	}

	// The CPEs only seem to look at the major and minor versions of the semantic version.
	majorMinorVersion := c.Version[:strings.LastIndex(c.Version, ".")]
	versionSet := set.NewStringSet(majorMinorVersion, escapePeriod(majorMinorVersion))

	// TODO: Remove logs
	attrs := common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
	logrus.Info(attrs)

	return attrs
}

func escapePeriod(str string) string {
	return strings.ReplaceAll(str, ".", `\.`)
}
