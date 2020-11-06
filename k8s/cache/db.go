package cache

import (
	"sync"
	"time"

	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/pkg/vulndump"
)

type cacheImpl struct {
	cacheRWLock sync.RWMutex
	// The expectation is that the number of Kubernetes vulns is rather low (100 or fewer).
	// Because of this, we just store the vulns in memory instead of in BoltDB.
	// Consider switching to BoltDB if this gets absurdly large (on the scale of NVD).
	cache map[string]*validation.CVESchema

	dir             string
	timeRWLock      sync.RWMutex
	lastUpdatedTime time.Time
}

func New() Cache {
	return &cacheImpl{
		cache: make(map[string]*validation.CVESchema),
		dir:   vulndump.K8sDirName,
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

func (c *cacheImpl) GetVulnForCVE(cve string) *validation.CVESchema {
	c.cacheRWLock.RLock()
	defer c.cacheRWLock.RUnlock()

	return c.cache[cve]
}
