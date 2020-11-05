package cache

import (
	"github.com/stackrox/scanner/pkg/vulndump"
	"sync"
	"time"

	"github.com/stackrox/k8s-cves/pkg/validation"
)

type cacheImpl struct {
	cache map[string]validation.CVESchema

	dir             string
	updateLock      sync.Mutex
	lastUpdatedTime time.Time
}

func New() Cache {
	return &cacheImpl{
		cache: make(map[string]validation.CVESchema),
		dir:   vulndump.K8sDirName,
	}
}

func (c *cacheImpl) Dir() string {
	return c.dir
}

func (c *cacheImpl) LoadFromDirectory(definitionsDir string) error {
	return nil
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
