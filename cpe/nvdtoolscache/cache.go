package nvdtoolscache

import (
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/wfn"
)

type Cache interface {
	GetVulnsForAttributes(attributes []*wfn.Attributes) ([]cvefeed.Vuln, error)
	LoadFromDirectory(dumpDir string) error
}
