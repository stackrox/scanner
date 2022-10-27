// This package exists to avoid import cycles.
package ziputil_test

import (
	"archive/zip"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/ziputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenFile(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testZip := filepath.Join(filepath.Dir(filename), "testdata/test.zip")

	zipR, err := zip.OpenReader(testZip)
	require.NoError(t, err)
	defer utils.IgnoreError(zipR.Close)

	m := repo2cpe.NewMapping()
	assert.NoError(t, m.LoadFromZip(&zipR.Reader, "rhelv2"))
}

func TestOpenFilesInDir(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testZip := filepath.Join(filepath.Dir(filename), "testdata/test.zip")

	zipR, err := zip.OpenReader(testZip)
	require.NoError(t, err)
	defer utils.IgnoreError(zipR.Close)

	rcs, err := ziputil.OpenFilesInDir(&zipR.Reader, "rhelv2/vulns", ".json")
	assert.NoError(t, err)
	assert.Len(t, rcs, 1)

	var rhel vulndump.RHELv2
	assert.NoError(t, json.NewDecoder(rcs[0]).Decode(&rhel))
}
