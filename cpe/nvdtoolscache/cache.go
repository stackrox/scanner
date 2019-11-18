package nvdtoolscache

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
)

type Cache interface {
	GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error)
	LoadFromDirectory(dumpDir string) error
}
