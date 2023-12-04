package vulndump

import (
	"archive/zip"
	"os"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stretchr/testify/require"
)

func BenchmarkLoadOSVulnsFromDump(b *testing.B) {
	f := mustFetchOSVulns(b)
	defer utils.IgnoreError(f.Close)

	benchmarkLoadOSVulnsFromDump(b, f)
}

func BenchmarkLoadOSVulnsFromDump_Offline(b *testing.B) {
	f := mustFetchOfflineOSVulns(b)
	defer utils.IgnoreError(f.Close)

	benchmarkLoadOSVulnsFromDump(b, f)
}

func benchmarkLoadOSVulnsFromDump(b *testing.B, f *os.File) {
	zipR, err := zip.OpenReader(f.Name())
	require.NoError(b, err)
	defer utils.IgnoreError(zipR.Close)

	runtime.GC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vulns, err := LoadOSVulnsFromDump(&zipR.Reader)
		require.NoError(b, err)
		b.Logf("Loaded %d vulns", len(vulns))
	}
}
