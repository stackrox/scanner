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
}
