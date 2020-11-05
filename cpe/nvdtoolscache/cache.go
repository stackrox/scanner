package nvdtoolscache

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/stackrox/scanner/pkg/cache"
)

type Cache interface {
	GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error)

	cache.Cache
}
