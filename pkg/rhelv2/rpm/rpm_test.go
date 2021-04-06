package rpm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPMFeatureDetection(t *testing.T) {
	sampleExpectedPkgs := []*database.Package{
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
	}

	unexpectedPkgs := []*database.Package{
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

	pkgs, cpes, err := ListFeatures(tarutil.FilesMap{
		"var/lib/rpm/Packages":                       d,
		"root/buildinfo/content_manifests/test.json": manifest,
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, cpes, expectedCPEs)
	assert.Subset(t, pkgs, sampleExpectedPkgs)
	assert.NotSubset(t, pkgs, unexpectedPkgs)
}
