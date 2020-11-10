package cache

import (
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/stackrox/k8s-cves/pkg/validation"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/vulndump"
)

type cacheImpl struct {
	cacheRWLock sync.RWMutex
	// The expectation is that the number of Kubernetes vulns is rather low (100 or fewer).
	// Because of this, we just store the vulns in memory instead of in BoltDB.
	// Consider switching to BoltDB if this gets absurdly large (on the scale of NVD).
	cache map[v1.KubernetesComponentRequest_KubernetesComponent]map[string]*validation.CVESchema
	// Vulns that are not associated with a particular component.
	unsetVulns []*validation.CVESchema

	dir             string
	timeRWLock      sync.RWMutex
	lastUpdatedTime time.Time
}

func New() Cache {
	return &cacheImpl{
		cache: make(map[v1.KubernetesComponentRequest_KubernetesComponent]map[string]*validation.CVESchema),
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

func (c *cacheImpl) GetVulnsByComponent(component v1.KubernetesComponentRequest_KubernetesComponent, v string) []*validation.CVESchema {
	c.cacheRWLock.RLock()
	defer c.cacheRWLock.RUnlock()

	var vulns []*validation.CVESchema
	for _, vuln := range c.cache[component] {
		if isAffected(v, vuln) {
			// Only return vulnerabilities relevant to the given version.
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

func isAffected(vStr string, vuln *validation.CVESchema) bool {
	v, err := version.NewVersion(vStr)
	if err != nil {
		return false
	}

	for _, affected := range vuln.Affected {
		constraint, err := version.NewConstraint(affected.Range)
		if err != nil {
			return false
		}
		if constraint.Check(v) {
			return true
		}
	}

	return false
}
