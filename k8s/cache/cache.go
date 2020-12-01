package cache

import (
	"github.com/stackrox/k8s-cves/pkg/validation"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/cache"
)

type Cache interface {
	GetVulnsByComponent(component v1.KubernetesComponent_KubernetesComponent, version string) []*validation.CVESchema

	cache.Cache
}
