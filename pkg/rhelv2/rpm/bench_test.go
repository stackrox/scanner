package rpm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stretchr/testify/require"
)

func BenchmarkListFeatures(b *testing.B) {
	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(b, err)

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/test.json"))
	require.NoError(b, err)

	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	b.Setenv("REPO_TO_CPE_DIR", cpesDir)

	filemap := tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
		"var/lib/rpm/Packages":                       {Contents: d},
		"root/buildinfo/content_manifests/test.json": {Contents: manifest},
		"usr/lib64/libz.so.1":                        {Executable: true},
		"usr/lib64/libz.so.1.2.11":                   {Executable: true},
		"usr/lib64/libform.so.6":                     {Executable: true},
		"usr/lib64/libncursesw.so.6.1":               {Executable: true},
		"usr/lib64/libpanelw.so.6":                   {Executable: true},
		"etc/redhat-release":                         {Executable: true},
		"etc/os-release":                             {Executable: true},
		"usr/lib/redhat-release":                     {Executable: true},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ListFeaturesTest(filemap)
	}
}
