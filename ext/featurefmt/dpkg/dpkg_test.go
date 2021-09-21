// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dpkg

import (
	"testing"

	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDpkgFeatureDetection(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "false")
	defer env.RestoreAll()

	testData := []featurefmt.TestData{
		// Test an Ubuntu dpkg status file
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear one time
				{
					Feature: database.Feature{Name: "pam"},
					Version: "1.1.8-3.1ubuntu3",
				},
				{
					Feature: database.Feature{Name: "makedev"},
					Version: "2.3.1-93ubuntu1",
				},
				{
					Feature: database.Feature{Name: "gcc-5"},
					Version: "5.1.1-12ubuntu1", // The version comes from the "Source:" line
				},
				{
					Feature: database.Feature{Name: "base-files"},
					Version: "10.3+deb10u6",
				},
				{
					Feature: database.Feature{Name: "netbase"},
					Version: "5.6",
				},
				{
					Feature: database.Feature{Name: "pkg-source"},
					Version: "1.1.8-3.1ubuntu3",
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/dpkg/status":           tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/status")},
				"var/lib/dpkg/status.d":         tarutil.FileData{},
				"var/lib/dpkg/status.d/base":    tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-base")},
				"var/lib/dpkg/status.d/netbase": tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-netbase")},
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}

func TestDpkgFeatureDetectionWithActiveVulnMgmt(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "true")
	defer env.RestoreAll()

	testData := []featurefmt.TestData{
		// Test an Ubuntu dpkg status file
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear one time
				{
					Feature:             database.Feature{Name: "pam"},
					Version:             "1.1.8-3.1ubuntu3",
					ProvidedExecutables: []string{"/another/one", "/test/executable"},
				},
				{
					Feature: database.Feature{Name: "makedev"},
					Version: "2.3.1-93ubuntu1",
				},
				{
					Feature:             database.Feature{Name: "gcc-5"},
					Version:             "5.1.1-12ubuntu1", // The version comes from the "Source:" line
					ProvidedExecutables: []string{"/i/am/an/executable"},
				},
				{
					Feature: database.Feature{Name: "base-files"},
					Version: "10.3+deb10u6",
				},
				{
					Feature: database.Feature{Name: "netbase"},
					Version: "5.6",
				},
				{
					Feature:             database.Feature{Name: "pkg-source"},
					Version:             "1.1.8-3.1ubuntu3",
					ProvidedExecutables: []string{"/exec-me", "/exec-me-2"},
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/dpkg/status":                       tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/status")},
				"var/lib/dpkg/status.d":                     tarutil.FileData{},
				"var/lib/dpkg/status.d/base":                tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-base")},
				"var/lib/dpkg/info/base-files.list":         tarutil.FileData{Contents: []byte{}},
				"var/lib/dpkg/status.d/netbase":             tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-netbase")},
				"var/lib/dpkg/info/netbase.list":            tarutil.FileData{Contents: []byte{}},
				"var/lib/dpkg/info/libpam-runtime.list":     tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/libpam-runtime.list")},
				"var/lib/dpkg/info/libpam-modules-bin.list": tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/libpam-modules-bin.list")},
				"var/lib/dpkg/info/libgcc1:amd64.list":      tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/libgcc1:amd64.list")},
				"test/executable":                           tarutil.FileData{Executable: true},
				"another/one":                               tarutil.FileData{Executable: true},
				"i/am/an/executable":                        tarutil.FileData{Executable: true},
				"var/lib/dpkg/info/pkg-source.list":         tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg-source.list")},
				"var/lib/dpkg/info/pkg1:amd64.list":         tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg1:amd64.list")},
				"var/lib/dpkg/info/pkg2.list":               tarutil.FileData{Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg2.list")},
				"exec-me":                                   tarutil.FileData{Executable: true},
				"exec-me-2":                                 tarutil.FileData{Executable: true},
				"my-jar.jar":                                tarutil.FileData{Contents: []byte("jar contents")},
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
