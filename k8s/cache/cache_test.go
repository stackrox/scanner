package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	cache := New()
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vuln := cache.GetVulnForCVE(`CVE-2020-1234`)
	assert.Equal(t, "CVE-2020-1234", vuln.CVE)
	assert.Equal(t, 6.3, vuln.CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N`, vuln.CVSS.NVD.VectorV3)

	require.Nil(t, cache.GetVulnForCVE(`CVE-2020-1235`))

	// Update cache.
	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))

	vuln = cache.GetVulnForCVE(`CVE-2020-1234`)
	assert.Equal(t, "CVE-2020-1234", vuln.CVE)
	assert.Equal(t, 7.7, vuln.CVSS.NVD.ScoreV3)
	assert.Equal(t, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`, vuln.CVSS.NVD.VectorV3)

	assert.NotNil(t, cache.GetVulnForCVE(`CVE-2020-1235`))
}
