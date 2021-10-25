package golang

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

// GetGolangAttributes returns the attributes from the given Golang component.
func GetGolangAttributes(c *component.Component) []*wfn.Attributes {
	nameParts := strings.Split(c.Name, "/")
	nameSet := set.NewStringSet(nameParts[len(nameParts)-1])
	var vendorSet set.StringSet
	if len(nameParts) > 1 {
		vendorSet = set.NewStringSet(strings.Join(nameParts[:len(nameParts)-1], "/"))
	}
	versionSet := set.NewStringSet(c.Version)

	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}
