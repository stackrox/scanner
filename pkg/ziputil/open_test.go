package ziputil

import (
	"archive/zip"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenFile(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testZip := filepath.Join(filepath.Dir(filename), "/testdata/test.zip")

	zipR, err := zip.OpenReader(testZip)
	require.NoError(t, err)
	defer utils.IgnoreError(zipR.Close)

	rc, err := OpenFile(zipR, "rhelv2/repository-to-cpe.json")
	assert.NoError(t, err)

	m := repo2cpe.NewMapping()
	assert.NoError(t, m.LoadFromReader(rc))
}

func TestOpenFilesInDir(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testZip := filepath.Join(filepath.Dir(filename), "/testdata/test.zip")

	zipR, err := zip.OpenReader(testZip)
	require.NoError(t, err)
	defer utils.IgnoreError(zipR.Close)

	rcs, err := OpenFilesInDir(zipR, "rhelv2/vulns", ".json")
	assert.NoError(t, err)
	assert.Len(t, rcs, 1)

	// Copied from vulndump package to prevent import cycle.
	var rhel struct {
		LastModified time.Time                       `json:"last_modified"`
		Vulns        []*database.RHELv2Vulnerability `json:"vulns"`
	}
	assert.NoError(t, json.NewDecoder(rcs[0]).Decode(&rhel))
}
