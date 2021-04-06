package rpm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPMFeatureDetection(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	d, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "/testdata/Packages"))
	require.NoError(t, err)

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

	pkgs, cpes, err := ListFeatures(tarutil.FilesMap{
		"var/lib/rpm/Packages": d,
	})
	assert.NoError(t, err)
	assert.Empty(t, cpes)
	assert.Subset(t, pkgs, sampleExpectedPkgs)
}
