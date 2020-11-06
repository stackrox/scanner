package cache

import (
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/pkg/cache"
)

type Cache interface {
	GetVulnForCVE(cve string) *validation.CVESchema

	cache.Cache
}
