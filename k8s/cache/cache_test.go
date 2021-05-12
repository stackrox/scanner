package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	cache := New()
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vulns := cache.GetVulnsByComponent(KubeProxy, "1.0.0")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, "CVE-2020-1234", vulns[0].CVE)
	assert.Equal(t, 6.3, vulns[0].CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N`, vulns[0].CVSS.NVD.VectorV3)

	// Out of range.
	assert.Empty(t, cache.GetVulnsByComponent(KubeProxy, "1.19.0"))
	// Also exists.
	assert.Equal(t, 1, len(cache.GetVulnsByComponent(Kubelet, "1.0.0")))
	// Does not exist.
	assert.Empty(t, cache.GetVulnsByComponent(Kubectl, "1.0.0"))

	// Update cache.
	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))

	vulns = cache.GetVulnsByComponent(KubeProxy, "1.0.0")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, "CVE-2020-1234", vulns[0].CVE)
	assert.Equal(t, 7.7, vulns[0].CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`, vulns[0].CVSS.NVD.VectorV3)

	assert.Equal(t, 2, len(cache.GetVulnsByComponent(Kubelet, "1.0.0")))
	assert.Equal(t, 1, len(cache.GetVulnsByComponent(Kubectl, "1.0.0")))

	// Generic vulns which do not have specific components
	vulns = cache.GetVulnsByComponent(Generic, "1.0.0")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, "CVE-2020-1238", vulns[0].CVE)
}
