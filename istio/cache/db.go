package cache

import (
	"sync"
	"time"

	"github.com/stackrox/istio-cves/types"
	"github.com/stackrox/scanner/pkg/istioUtil"
	"github.com/stackrox/scanner/pkg/vulndump"
)

var (
	_ Cache = (*cacheImpl)(nil)
)

type cacheImpl struct {
	cacheRWLock sync.RWMutex

	cache map[string]types.Vuln

	dir             string
	timeRWLock      sync.RWMutex
	lastUpdatedTime time.Time
}

func (c *cacheImpl) GetVulnsByVersion(version string) []types.Vuln {
	c.cacheRWLock.RLock()
	defer c.cacheRWLock.RUnlock()

	var vulns []types.Vuln
	for _, vuln := range c.cache {
		isAffected, _, _ := istioUtil.IstioIsAffected(version, vuln)
		if isAffected {
			// Only return vulnerabilities relevant to the given version.
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// New returns a new Istio vulnerability cache.
func New() Cache {
	return &cacheImpl{
		cache: make(map[string]types.Vuln),
		dir:   vulndump.IstioDirName,
	}
}

func (c *cacheImpl) Dir() string {
	return c.dir
}

func (c *cacheImpl) GetLastUpdate() time.Time {
	c.timeRWLock.RLock()
	defer c.timeRWLock.RUnlock()

	return c.lastUpdatedTime
}

func (c *cacheImpl) SetLastUpdate(t time.Time) {
	c.timeRWLock.Lock()
	defer c.timeRWLock.Unlock()

	c.lastUpdatedTime = t
}
