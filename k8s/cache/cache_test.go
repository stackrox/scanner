package cache

import (
	"testing"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	cache := New()
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vulns := cache.GetVulnsByComponent(v1.KubernetesComponent_KUBE_PROXY, "1.0.0")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, "CVE-2020-1234", vulns[0].CVE)
	assert.Equal(t, 6.3, vulns[0].CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N`, vulns[0].CVSS.NVD.VectorV3)

	// Out of range.
	assert.Empty(t, cache.GetVulnsByComponent(v1.KubernetesComponent_KUBE_PROXY, "1.19.0"))
	// Also exists.
	assert.Equal(t, 1, len(cache.GetVulnsByComponent(v1.KubernetesComponent_KUBELET, "1.0.0")))
	// Does not exist.
	assert.Empty(t, cache.GetVulnsByComponent(v1.KubernetesComponent_KUBECTL, "1.0.0"))

	// Update cache.
	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))

	vulns = cache.GetVulnsByComponent(v1.KubernetesComponent_KUBE_PROXY, "1.0.0")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, "CVE-2020-1234", vulns[0].CVE)
	assert.Equal(t, 7.7, vulns[0].CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`, vulns[0].CVSS.NVD.VectorV3)

	assert.Equal(t, 2, len(cache.GetVulnsByComponent(v1.KubernetesComponent_KUBELET, "1.0.0")))
	assert.Equal(t, 1, len(cache.GetVulnsByComponent(v1.KubernetesComponent_KUBECTL, "1.0.0")))
}
