package ziputil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "extract_test")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	_, filename, _, _ := runtime.Caller(0)
	testZip := filepath.Join(filepath.Dir(filename), "/testdata/test.zip")

	// Test k8s.
	err = Extract(testZip, "k8s", tmpDir)
	require.NoError(t, err)
	fileInfo, err := os.Stat(filepath.Join(tmpDir, "k8s/CVE-2020-8552.yaml"))
	require.NoError(t, err)
	assert.False(t, fileInfo.IsDir())

	// Test nvd.
	err = Extract(testZip, "nvd", tmpDir)
	require.NoError(t, err)
	fileInfo, err = os.Stat(filepath.Join(tmpDir, "nvd/2002.json"))
	require.NoError(t, err)
	assert.False(t, fileInfo.IsDir())

	// Test RHELv2 sub-directory.
	err = Extract(testZip, "rhelv2/vulns", tmpDir)
	require.NoError(t, err)
	fileInfo, err = os.Stat(filepath.Join(tmpDir, "rhelv2/vulns/RHEL6-amq-clients-1-including-unpatched.json"))
	require.NoError(t, err)
	assert.False(t, fileInfo.IsDir())

	// Test RHELv2 file.
	err = Extract(testZip, "rhelv2/repository-to-cpe.json", tmpDir)
	require.NoError(t, err)
	fileInfo, err = os.Stat(filepath.Join(tmpDir, "rhelv2/repository-to-cpe.json"))
	require.NoError(t, err)
	assert.False(t, fileInfo.IsDir())
}
