package nvdtoolscache

import (
	"os"
	"sync"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	lock           sync.RWMutex
	cacheInstance  *cvefeed.Cache
	cveMapInstance *map[string]*Vuln
)

func Get() (*cvefeed.Cache, map[string]*Vuln) {
	lock.RLock()
	defer lock.RUnlock()
	return cacheInstance, *cveMapInstance
}

func set(cache *cvefeed.Cache, cveMap map[string]*Vuln) {
	lock.Lock()
	defer lock.Unlock()
	cacheInstance = cache
	cveMapInstance = &cveMap
}

func init() {
	definitionsDir := os.Getenv("NVD_DEFINITIONS_DIR")
	if definitionsDir == "" {
		return
	}
	utils.Must(LoadFromDirectory(definitionsDir))

}
