package cache

import (
	"sync"
	"time"

	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/pkg/vulndump"
)

type cacheImpl struct {
	// The expectation is that the number of Kubernetes vulns is rather low (100 or fewer).
	// Because of this, we just store the vulns in memory instead of in BoltDB.
	// Consider switching to BoltDB if this gets absurdly large (on the scale of NVD).
	cache map[string]*validation.CVESchema

	dir             string
	updateLock      sync.Mutex
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
	c.updateLock.Lock()
	defer c.updateLock.Unlock()

	return c.lastUpdatedTime
}

func (c *cacheImpl) SetLastUpdate(t time.Time) {
	c.updateLock.Lock()
	defer c.updateLock.Unlock()

	c.lastUpdatedTime = t
}
