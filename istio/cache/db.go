package cache

import (
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/istio-cves/types"
	"github.com/stackrox/scanner/pkg/istioutil"
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

func (c *cacheImpl) GetVulnsByVersion(vStr string) []types.Vuln {
	c.cacheRWLock.RLock()
	defer c.cacheRWLock.RUnlock()

	var vulns []types.Vuln
	v, err := version.NewVersion(vStr)
	if err != nil {
		log.Infof("Failed to get version: %s", vStr)
		return nil
	}
	for _, vuln := range c.cache {
		isAffected, _, error := istioutil.IsAffected(v, vuln)
		if error != nil {
			continue
		}
		if isAffected {
			// Only return vulnerabilities relevant to the given vStr.
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
