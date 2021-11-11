package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValdiateUUID(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	// Test parsing testdata/fetcher_debian_test.json
	genesisFile, err := os.Open(filepath.Join(filepath.Dir(filename), "../../image/scanner/dump/genesis_manifests.json"))
	require.NoError(t, err)
	var manifest genesisManifest
	require.NoError(t, json.NewDecoder(genesisFile).Decode(&manifest))

	for _, dump := range manifest.KnownGenesisDumps[1:] {
		assert.NoError(t, validateUUID(dump.UUID))
	}

	assert.Error(t, validateUUID("invalid"))
}

func TestGetURL(t *testing.T) {
	centralEndpoint := "https://central.stackrox.svc"
	centralEndpoint = urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)

	uuid := "55b9538d-0d42-4bbd-b4d4-5d31421e7302"
	url, err := getURL(centralEndpoint, uuid)
	assert.NoError(t, err)
	expected := "https://central.stackrox.svc/api/extensions/scannerdefinitions?uuid=55b9538d-0d42-4bbd-b4d4-5d31421e7302"
	assert.Equal(t, expected, url)
}
