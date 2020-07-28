package nvdtoolscache

import (
	"os"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/stackrox/rox/pkg/bolthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustGetVuln(t *testing.T, cache Cache, product string) cvefeed.Vuln {
	vulns, err := cache.GetVulnsForProducts([]string{product})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	return vulns[0]
}

func TestCache(t *testing.T) {
	db, err := bolthelper.NewTemp(t.Name())
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
		_ = os.RemoveAll(db.Path())
	}()

	cache := newWithDB(db)
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vuln := mustGetVuln(t, cache, `yargs\-parser`)
	assert.Equal(t, "CVE-2020-7608", vuln.ID())
	assert.Equal(t, 6.5, vuln.CVSSv3BaseScore())

	vuln = mustGetVuln(t, cache, `tomcat`)
	assert.Equal(t, "CVE-2020-1745", vuln.ID())
	assert.Equal(t, 4, len(vuln.Config()))

	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))
	vuln = mustGetVuln(t, cache, `yargs\-parser`)
	assert.Equal(t, vuln.ID(), "CVE-2020-7608")
	assert.Equal(t, 5.3, vuln.CVSSv3BaseScore())

	vuln = mustGetVuln(t, cache, `undertow`)
	assert.Equal(t, "CVE-2020-1745", vuln.ID())
	assert.Equal(t, 1, len(vuln.Config()))
}
