package cache

import (
	"github.com/stackrox/istio-cves/types"
	"github.com/stackrox/scanner/pkg/cache"
)

// Cache defines a Kubernetes vulnerability cache.
type Cache interface {
	GetVulnsByVersion(version string) []types.Vuln

	cache.Cache
}
