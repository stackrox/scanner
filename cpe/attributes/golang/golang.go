package golang

import (
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/pkg/component"
)

// GetGolangAttributes returns the attributes from the given Golang component.
func GetGolangAttributes(c *component.Component) []*wfn.Attributes {
	if c.Name == "golang" {
		return []*wfn.Attributes{
			{
				Part:    "a",
				Vendor:  "golang",
				Product: "go",
				Version: escapePeriod(c.Version),
			},
		}
	}

	return []*wfn.Attributes{
		{
			Part:    "a",
			Product: c.Name,
			Version: escapePeriod(c.Version),
		},
	}
}

func escapePeriod(str string) string {
	return strings.ReplaceAll(str, ".", `\.`)
}
