package golang

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	packageNameRegex = regexp.MustCompile(`^.*/([^/]+(?:/v\d+)?)$`)
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

	pkgNameMatches := packageNameRegex.FindStringSubmatch(c.Name)
	if len(pkgNameMatches) != 2 {
		return nil
	}

	pkgName := pkgNameMatches[1]
	pkgVendor := "golang:" + strings.TrimSuffix(c.Name, "/"+pkgName)

	return []*wfn.Attributes{
		{
			Part:    "a",
			Vendor:  pkgVendor,
			Product: pkgName,
			Version: escapePeriod(c.Version),
		},
	}
}

func escapePeriod(str string) string {
	return strings.ReplaceAll(str, ".", `\.`)
}
