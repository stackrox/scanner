package nvdtoolscache

import (
	"os"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/stackrox/scanner/pkg/bolthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustGetVulnForProduct(t *testing.T, cache Cache, product string) cvefeed.Vuln {
	vulns, err := cache.GetVulnsForProducts([]string{product})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	return vulns[0]
}

func mustNotGetVulnForProduct(t *testing.T, cache Cache, product string) bool {
	vulns, err := cache.GetVulnsForProducts([]string{product})
	require.NoError(t, err)
	return len(vulns) == 0
}

func mustGetVulnForComponent(t *testing.T, cache Cache, vendor, product, version string) *NVDCVEItemWithFixedIn {
	vulns, err := cache.GetVulnsForComponent(vendor, product, version)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	return vulns[0]
}

func mustNotGetVulnForComponent(t *testing.T, cache Cache, vendor, product, version string) bool {
	vulns, err := cache.GetVulnsForComponent(vendor, product, version)
	require.NoError(t, err)
	return len(vulns) == 0
}

// Tests both loading, updating, and GetVulnsByProducts.
func TestCache(t *testing.T) {
	db, err := bolthelper.NewTemp(t.Name())
	require.NoError(t, err)
	err = initializeDB(db)
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
		_ = os.RemoveAll(db.Path())
	}()

	// Initialize cache.
	cache := newWithDB(db)
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vuln := mustGetVulnForProduct(t, cache, `yargs\-parser`)
	assert.Equal(t, "CVE-2020-7608", vuln.ID())
	assert.Equal(t, 6.5, vuln.CVSSv3BaseScore())

	vuln = mustGetVulnForProduct(t, cache, `tomcat`)
	assert.Equal(t, "CVE-2020-1745", vuln.ID())
	assert.Equal(t, 4, len(vuln.Config()))

	assert.True(t, mustNotGetVulnForProduct(t, cache, `undertow`))

	// Update cache.
	require.NoError(t, cache.LoadFromDirectory("./testdata/after"))

	vuln = mustGetVulnForProduct(t, cache, `yargs\-parser`)
	assert.Equal(t, "CVE-2020-7608", vuln.ID())
	assert.Equal(t, 5.3, vuln.CVSSv3BaseScore())

	vuln = mustGetVulnForProduct(t, cache, `undertow`)
	assert.Equal(t, "CVE-2020-1745", vuln.ID())
	assert.Equal(t, 1, len(vuln.Config()))

	assert.True(t, mustNotGetVulnForProduct(t, cache, `tomcat`))
}

func TestGetVulnsForComponent(t *testing.T) {
	db, err := bolthelper.NewTemp(t.Name())
	require.NoError(t, err)
	err = initializeDB(db)
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
		_ = os.RemoveAll(db.Path())
	}()

	// Initialize cache.
	cache := newWithDB(db)
	require.NoError(t, cache.LoadFromDirectory("./testdata/before"))

	vuln := mustGetVulnForComponent(t, cache, `yargs`, `yargs-parser`, `12.0.0`)
	assert.Equal(t, `CVE-2020-7608`, vuln.CVE.CVEDataMeta.ID)
	assert.Equal(t, "13.1.2", vuln.FixedIn)

	// Try different version.
	vuln = mustGetVulnForComponent(t, cache, `yargs`, `yargs-parser`, `17.0.2`)
	assert.Equal(t, `CVE-2020-7608`, vuln.CVE.CVEDataMeta.ID)
	assert.Equal(t, "18.1.1", vuln.FixedIn)

	// Try different product.
	vuln = mustGetVulnForComponent(t, cache, `apache`, `tomcat`, `7.0.0`)
	assert.Equal(t, `CVE-2020-1745`, vuln.CVE.CVEDataMeta.ID)
	assert.Equal(t, "7.0.100", vuln.FixedIn)

	// Try incorrect vendor.
	assert.True(t, mustNotGetVulnForComponent(t, cache, `notapache`, `tomcat`, `7.0.0`))

	// Try out of range version.
	assert.True(t, mustNotGetVulnForComponent(t, cache, `apache`, `tomcat`, `10.0.0`))

	// Linux Kernel
	vuln = mustGetVulnForComponent(t, cache, `linux`, `linux_kernel`, `5.9.0`)
	assert.Equal(t, `CVE-2020-27675`, vuln.CVE.CVEDataMeta.ID)
	assert.Equal(t, "", vuln.FixedIn)
}
