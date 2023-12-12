package vulndump

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/ziputil"
	"github.com/stretchr/testify/require"
)

const (
	defURL     = "https://definitions.stackrox.io/93AEC554-29EE-4E24-96D6-744092A98444/diff.zip"
	offlineURL = "https://install.stackrox.io/scanner/scanner-vuln-updates.zip"
)

func mustFetchOSVulns(b *testing.B) *os.File {
	f, err := os.Create(filepath.Join(b.TempDir(), "vulns.zip"))
	require.NoError(b, err)

	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(defURL)
	require.NoError(b, err)
	defer utils.IgnoreError(resp.Body.Close)

	_, err = io.Copy(f, resp.Body)
	require.NoError(b, err)

	return f
}

func mustFetchOfflineOSVulns(b *testing.B) *os.File {
	tmpPath := filepath.Join(b.TempDir(), "tmp.zip")
	tmpF, err := os.Create(tmpPath)
	require.NoError(b, err)
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	defer utils.IgnoreError(tmpF.Close)

	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(offlineURL)
	require.NoError(b, err)
	defer utils.IgnoreError(resp.Body.Close)

	_, err = io.Copy(tmpF, resp.Body)
	require.NoError(b, err)

	tmpZIP, err := zip.OpenReader(tmpPath)
	require.NoError(b, err)
	defer utils.IgnoreError(tmpZIP.Close)
	rc, err := ziputil.OpenFile(&tmpZIP.Reader, "scanner-defs.zip")
	require.NoError(b, err)
	defer utils.IgnoreError(rc.Close)

	f, err := os.Create(filepath.Join(b.TempDir(), "vulns.zip"))
	require.NoError(b, err)

	_, err = io.Copy(f, rc)
	require.NoError(b, err)

	return f
}

func BenchmarkOSLoader(b *testing.B) {
	f := mustFetchOSVulns(b)
	defer utils.IgnoreError(f.Close)

	benchmarkOSLoader(b, f)
}

func BenchmarkOSLoader_Offline(b *testing.B) {
	f := mustFetchOfflineOSVulns(b)
	defer utils.IgnoreError(f.Close)

	benchmarkOSLoader(b, f)
}

func benchmarkOSLoader(b *testing.B, f *os.File) {
	zipR, err := zip.OpenReader(f.Name())
	require.NoError(b, err)
	defer utils.IgnoreError(zipR.Close)
	vulnsF, err := ziputil.OpenFile(&zipR.Reader, OSVulnsFileName)
	require.NoError(b, err)
	defer utils.IgnoreError(vulnsF.Close)

	runtime.GC()

	loader, err := newOSLoader(vulnsF)
	require.NoError(b, err)
	defer func() {
		require.NoError(b, loader.Close())
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var n int
		for loader.Next() {
			vulns := loader.Vulns()
			n += len(vulns)
		}
		require.NoError(b, loader.Err())
		b.Logf("Loaded %d vulns", n)
	}
}
