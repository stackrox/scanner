package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	cache := New()
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))
	vulns := cache.GetVulnsByVersion("1.13.6")
	assert.Equal(t, 1, len(vulns))
	assert.Equal(t, vulns[0].CVSS.ScoreV3, 5.9)
	// Out of range.
	assert.Empty(t, cache.GetVulnsByVersion("1.15.6"))

	// Update cache.
	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))
	vulns2 := cache.GetVulnsByVersion("1.13.6")
	assert.Equal(t, 1, len(vulns2))
	assert.Equal(t, vulns2[0].CVSS.ScoreV3, 7.5)
}
