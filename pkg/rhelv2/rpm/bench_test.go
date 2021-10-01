package rpm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func BenchmarkListFeaturesNoActiveVulnMgmt(b *testing.B) {
	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(b, err)

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/test.json"))
	require.NoError(b, err)

	envIsolator := testutils.NewEnvIsolator(b)
	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("REPO_TO_CPE_DIR", cpesDir)
	envIsolator.Setenv(features.ActiveVulnMgmt.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	filemap := tarutil.FilesMap{
		"var/lib/rpm/Packages":                       tarutil.FileData{Contents: d},
		"root/buildinfo/content_manifests/test.json": tarutil.FileData{Contents: manifest},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ListFeaturesTest(filemap)
	}
}

func BenchmarkListFeatures(b *testing.B) {
	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(b, err)

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/test.json"))
	require.NoError(b, err)

	envIsolator := testutils.NewEnvIsolator(b)
	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("REPO_TO_CPE_DIR", cpesDir)
	envIsolator.Setenv(features.ActiveVulnMgmt.EnvVar(), "true")
	defer envIsolator.RestoreAll()

	filemap := tarutil.FilesMap{
		"var/lib/rpm/Packages":                       tarutil.FileData{Contents: d},
		"root/buildinfo/content_manifests/test.json": tarutil.FileData{Contents: manifest},
		"usr/lib64/libz.so.1":                        tarutil.FileData{Executable: true},
		"usr/lib64/libz.so.1.2.11":                   tarutil.FileData{Executable: true},
		"usr/lib64/libform.so.6":                     tarutil.FileData{Executable: true},
		"usr/lib64/libncursesw.so.6.1":               tarutil.FileData{Executable: true},
		"usr/lib64/libpanelw.so.6":                   tarutil.FileData{Executable: true},
		"etc/redhat-release":                         tarutil.FileData{Executable: true},
		"etc/os-release":                             tarutil.FileData{Executable: true},
		"usr/lib/redhat-release":                     tarutil.FileData{Executable: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ListFeaturesTest(filemap)
	}
}
