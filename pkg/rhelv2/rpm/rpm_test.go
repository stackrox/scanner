package rpm

import (
	"fmt"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

var testDirectory string

func init() {
	_, filename, _, _ := runtime.Caller(0)
	testDirectory = filepath.Dir(filename)
}

// ListFeaturesTest does the same as ListFeatures but should only be used for testing.
func ListFeaturesTest(files tarutil.LayerFiles) ([]*database.RHELv2Package, []string, error) {
	if features.ActiveVulnMgmt.Enabled() {
		return listFeatures(files, queryFmtActiveVulnMgmtTest)
	}
	return listFeatures(files, queryFmtTest)
}

func Test_listFeatures(t *testing.T) {
	type args struct {
		layerFiles tarutil.LayerFiles
		queryFmt   string
	}
	tests := []struct {
		name string
		args args

		// Add test layer files from a map of file data.
		files map[string]tarutil.FileData
		// Add test layer files from a map of files stored in the testdata/
		// directory.
		filesFromTestData map[string]string
		// Sets the queryFmt to test base on active vulnerability flag.
		isActiveVulnMngt bool

		// Expected values for assertion.
		sampleExpectedPkgs []*database.RHELv2Package
		unexpectedPkgs     []*database.RHELv2Package
		expectedCPEs       []string
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name: "TestRPMFeatureDetection with BerkeleyDB",
			filesFromTestData: map[string]string{
				"root/buildinfo/content_manifests/test.json": "test.json",
				"var/lib/rpm/Packages":                       "Packages",
			},
			isActiveVulnMngt: false,
			wantErr:          assert.NoError,
			sampleExpectedPkgs: []*database.RHELv2Package{
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
			},
			unexpectedPkgs: []*database.RHELv2Package{
				{
					Name:    "gpg-pubkey",
					Version: "d4082792-5b32db75",
				},
			},
			expectedCPEs: []string{
				"cpe:/o:redhat:enterprise_linux:8::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
			},
		},
		{
			name: "TestRPMFeatureDetectionWithActiveVulnMgmt with BerkleyDB",
			files: map[string]tarutil.FileData{
				"usr/lib64/libz.so.1":          {Executable: true},
				"usr/lib64/libz.so.1.2.11":     {Executable: true},
				"usr/lib64/libform.so.6":       {Executable: true},
				"usr/lib64/libncursesw.so.6.1": {Executable: true},
				"usr/lib64/libpanelw.so.6":     {Executable: true},
				"etc/redhat-release":           {Executable: true},
				"etc/os-release":               {Executable: true},
				"usr/lib/redhat-release":       {Executable: true},
			},
			filesFromTestData: map[string]string{
				"root/buildinfo/content_manifests/test.json": "test.json",
				"var/lib/rpm/Packages":                       "Packages",
			},
			isActiveVulnMngt: true,
			wantErr:          assert.NoError,
			sampleExpectedPkgs: []*database.RHELv2Package{
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
			},
			unexpectedPkgs: []*database.RHELv2Package{
				{
					Name:    "gpg-pubkey",
					Version: "d4082792-5b32db75",
				},
			},
			expectedCPEs: []string{
				"cpe:/o:redhat:enterprise_linux:8::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
			},
		},
		{
			name: "TestRPMFeatureDetection with SQLite",
			filesFromTestData: map[string]string{
				"root/buildinfo/content_manifests/test.json": "test.json",
				"var/lib/rpm/rpmdb.sqlite":                   "rpmdb.sqlite",
				"var/lib/rpm/rpmdb.sqlite-shm":               "rpmdb.sqlite-shm",
				"var/lib/rpm/rpmdb.sqlite-wal":               "rpmdb.sqlite-wal",
			},
			isActiveVulnMngt: false,
			wantErr:          assert.NoError,
			sampleExpectedPkgs: []*database.RHELv2Package{
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
			},
			unexpectedPkgs: []*database.RHELv2Package{
				{
					Name:    "gpg-pubkey",
					Version: "d4082792-5b32db75",
				},
			},
			expectedCPEs: []string{
				"cpe:/o:redhat:enterprise_linux:8::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
			},
		},
		{
			name: "TestRPMFeatureDetectionWithActiveVulnMgmt with SQLite",
			files: map[string]tarutil.FileData{
				"usr/lib64/libz.so.1":          {Executable: true},
				"usr/lib64/libz.so.1.2.11":     {Executable: true},
				"usr/lib64/libform.so.6":       {Executable: true},
				"usr/lib64/libncursesw.so.6.1": {Executable: true},
				"usr/lib64/libpanelw.so.6":     {Executable: true},
				"etc/redhat-release":           {Executable: true},
				"etc/os-release":               {Executable: true},
				"usr/lib/redhat-release":       {Executable: true},
			},
			filesFromTestData: map[string]string{
				"root/buildinfo/content_manifests/test.json": "test.json",
				"var/lib/rpm/rpmdb.sqlite":                   "rpmdb.sqlite",
				"var/lib/rpm/rpmdb.sqlite-shm":               "rpmdb.sqlite-shm",
				"var/lib/rpm/rpmdb.sqlite-wal":               "rpmdb.sqlite-wal",
			},
			isActiveVulnMngt: true,
			wantErr:          assert.NoError,
			sampleExpectedPkgs: []*database.RHELv2Package{
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
			},
			unexpectedPkgs: []*database.RHELv2Package{
				{
					Name:    "gpg-pubkey",
					Version: "d4082792-5b32db75",
				},
			},
			expectedCPEs: []string{
				"cpe:/o:redhat:enterprise_linux:8::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
			},
		},
	}

	for _, tt := range tests {
		// Initialize test arguments.
		tt.args.queryFmt = queryFmtTest
		if tt.isActiveVulnMngt {
			tt.args.queryFmt = queryFmtActiveVulnMgmtTest
		}
		if tt.filesFromTestData != nil {
			if tt.files == nil {
				tt.files = make(map[string]tarutil.FileData)
			}
			for n, f := range tt.filesFromTestData {
				c, err := os.ReadFile(filepath.Join(testDirectory, "testdata", f))
				require.NoError(t, err)
				tt.files[n] = tarutil.FileData{Contents: c}
			}
		}
		tt.args.layerFiles = tarutil.CreateNewLayerFiles(tt.files)

		// Run test.
		t.Run(tt.name, func(t *testing.T) {
			envIsolator := testutils.NewEnvIsolator(t)
			defer envIsolator.RestoreAll()
			envIsolator.Setenv("REPO_TO_CPE_DIR", filepath.Join(testDirectory, "/testdata"))
			tt.args.layerFiles = tarutil.CreateNewLayerFiles(tt.files)

			// Functions call.
			pkgs, cpes, err := listFeatures(tt.args.layerFiles, tt.args.queryFmt)

			// Assertions.
			if !tt.wantErr(t, err, fmt.Sprintf("listFeatures(%v, %v)", tt.args.layerFiles, tt.args.queryFmt)) {
				return
			}
			assert.ElementsMatch(t, cpes, tt.expectedCPEs)
			assert.Subset(t, pkgs, tt.sampleExpectedPkgs)
			assert.NotSubset(t, pkgs, tt.unexpectedPkgs)
		})
	}
}
