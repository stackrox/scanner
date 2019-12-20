package nvdtoolscache

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/stackrox/scanner/pkg/vulndump"
)

type Cache interface {
	GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error)

	vulndump.InMemNVDCache
}
