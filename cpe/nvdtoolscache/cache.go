package nvdtoolscache

import (
	"archive/zip"

	"github.com/facebookincubator/nvdtools/cvefeed"
)

type Cache interface {
	GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error)
	LoadFromDirectory(dumpDir string) error
	LoadFromZip(zipR *zip.Reader) error
}
