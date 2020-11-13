package dotnetcoreruntime

import (
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

func GetDotNetCoreRuntimeAttributes(c *component.Component) []*wfn.Attributes {
	vendorSet := set.NewStringSet("microsoft")

	nameSet := set.NewStringSet(c.Name, escapePeriod(c.Name))
	versionSet := set.NewStringSet()
	if filepath.Ext(c.Location) == ".dll" {
		// If the file is a DLL, then the version strings are of the format 4.0.0.0
		// but the vulnerabilities only describe in the style of 4.0.0
		version := c.Version
		if lastIdx := strings.LastIndex(c.Version, "."); lastIdx != -1 {
			version = version[:lastIdx]
		}
		versionSet.AddAll(version, escapePeriod(version))
	} else {
		versionSet.AddAll(c.Version, escapePeriod(c.Version))
	}
	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}

func escapePeriod(str string) string {
	return strings.ReplaceAll(str, ".", `\.`)
}
