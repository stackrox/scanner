package rpm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ListFeaturesTest does the same as ListFeatures but should only be used for testing.
func ListFeaturesTest(files tarutil.FilesMap) ([]*database.RHELv2Package, []string, error) {
	if features.ActiveVulnMgmt.Enabled() {
		return listFeatures(files, queryFmtActiveVulnMgmtTest)
	}
	return listFeatures(files, queryFmtTest)
}

func TestRPMFeatureDetection(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "false")
	defer env.RestoreAll()

	sampleExpectedPkgs := []*database.RHELv2Package{
		{
			Name:    "zlib",
			Version: "1.2.11-16.el8_2",
			Arch:    "x86_64",
		},
		{
			Name:    "dbus-common",
			Version: "1:1.12.8-12.el8_3",
			Arch:    "noarch",
		},
		{
			Name:    "ncurses-libs",
			Version: "6.1-7.20180224.el8",
			Arch:    "x86_64",
		},
		{
			Name:    "redhat-release",
			Version: "8.3-1.0.el8",
			Arch:    "x86_64",
		},
	}

	unexpectedPkgs := []*database.RHELv2Package{
		{
			Name:    "gpg-pubkey",
			Version: "d4082792-5b32db75",
		},
	}

	expectedCPEs := []string{
		"cpe:/o:redhat:enterprise_linux:8::baseos",
		"cpe:/a:redhat:enterprise_linux:8::appstream",
	}

	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(t, err)

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/test.json"))
	require.NoError(t, err)

	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()
	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("REPO_TO_CPE_DIR", cpesDir)

	pkgs, cpes, err := ListFeaturesTest(tarutil.FilesMap{
		"var/lib/rpm/Packages":                       tarutil.FileData{Contents: d},
		"root/buildinfo/content_manifests/test.json": tarutil.FileData{Contents: manifest},
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, cpes, expectedCPEs)
	assert.Subset(t, pkgs, sampleExpectedPkgs)
	assert.NotSubset(t, pkgs, unexpectedPkgs)
}

func TestRPMFeatureDetectionWithActiveVulnMgmt(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "true")
	defer env.RestoreAll()

	sampleExpectedPkgs := []*database.RHELv2Package{
		{
			Name:    "zlib",
			Version: "1.2.11-16.el8_2",
			Arch:    "x86_64",
			ExecutableToDependencies: database.StringToStringsMap{
				"/usr/lib64/libz.so.1":      {},
				"/usr/lib64/libz.so.1.2.11": {},
			},
		},
		{
			Name:    "dbus-common",
			Version: "1:1.12.8-12.el8_3",
			Arch:    "noarch",
		},
		{
			Name:    "ncurses-libs",
			Version: "6.1-7.20180224.el8",
			Arch:    "x86_64",
			ExecutableToDependencies: database.StringToStringsMap{
				"/usr/lib64/libform.so.6":       {},
				"/usr/lib64/libncursesw.so.6.1": {},
				"/usr/lib64/libpanelw.so.6":     {},
			},
		},
		{
			Name:    "redhat-release",
			Version: "8.3-1.0.el8",
			Arch:    "x86_64",
		},
	}

	unexpectedPkgs := []*database.RHELv2Package{
		{
			Name:    "gpg-pubkey",
			Version: "d4082792-5b32db75",
		},
	}

	expectedCPEs := []string{
		"cpe:/o:redhat:enterprise_linux:8::baseos",
		"cpe:/a:redhat:enterprise_linux:8::appstream",
	}

	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(t, err)

	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/test.json"))
	require.NoError(t, err)

	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()
	cpesDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("REPO_TO_CPE_DIR", cpesDir)

	pkgs, cpes, err := ListFeaturesTest(tarutil.FilesMap{
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
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, cpes, expectedCPEs)
	assert.Subset(t, pkgs, sampleExpectedPkgs)
	assert.NotSubset(t, pkgs, unexpectedPkgs)
}
