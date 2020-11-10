package nvdtoolscache

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stackrox/scanner/pkg/cache"
)

type Cache interface {
	GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error)
	GetVulnsForComponent(vendor, product, version string) ([]*NVDCVEItemWithFixedIn, error)

	cache.Cache
}

type NVDCVEItemWithFixedIn struct {
	*schema.NVDCVEFeedJSON10DefCVEItem
	FixedIn string
}
