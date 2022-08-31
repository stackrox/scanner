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

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/elf"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDpkgFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		// Test an Ubuntu dpkg status file
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear one time
				{
					Feature:                  database.Feature{Name: "pam"},
					Version:                  "1.1.8-3.1ubuntu3",
					ExecutableToDependencies: database.StringToStringsMap{"/another/one": {}, "/test/executable": {}},
				},
				{
					Feature: database.Feature{Name: "makedev"},
					Version: "2.3.1-93ubuntu1",
				},
				{
					Feature:                  database.Feature{Name: "gcc-5"},
					Version:                  "5.1.1-12ubuntu1", // The version comes from the "Source:" line
					ExecutableToDependencies: database.StringToStringsMap{"/i/am/an/executable": {}},
					LibraryToDependencies:    database.StringToStringsMap{"gcc5.so.1": {}},
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
					Feature:                  database.Feature{Name: "pkg-source"},
					Version:                  "1.1.8-3.1ubuntu3",
					ExecutableToDependencies: database.StringToStringsMap{"/exec-me": {}, "/exec-me-2": {"gcc5.so.1": {}}},
					LibraryToDependencies:    database.StringToStringsMap{"somelib.so.1": {"gcc5.so.1": {}}},
				},
			},
			Files: tarutil.CreateNewLayerFiles(
				map[string]analyzer.FileData{
					"var/lib/dpkg/status":                       {Contents: featurefmt.LoadFileForTest("dpkg/testdata/status")},
					"var/lib/dpkg/status.d":                     {},
					"var/lib/dpkg/status.d/base":                {Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-base")},
					"var/lib/dpkg/info/base-files.list":         {Contents: []byte{}},
					"var/lib/dpkg/status.d/netbase":             {Contents: featurefmt.LoadFileForTest("dpkg/testdata/statusd-netbase")},
					"var/lib/dpkg/info/netbase.list":            {Contents: []byte{}},
					"var/lib/dpkg/info/libpam-runtime.list":     {Contents: featurefmt.LoadFileForTest("dpkg/testdata/libpam-runtime.list")},
					"var/lib/dpkg/info/libpam-modules-bin.list": {Contents: featurefmt.LoadFileForTest("dpkg/testdata/libpam-modules-bin.list")},
					"var/lib/dpkg/info/libgcc1:amd64.list":      {Contents: featurefmt.LoadFileForTest("dpkg/testdata/libgcc1:amd64.list")},
					"test/executable":                           {Executable: true},
					"another/one":                               {Executable: true},
					"i/am/an/executable":                        {Executable: true},
					"var/lib/dpkg/info/pkg-source.list":         {Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg-source.list")},
					"var/lib/dpkg/info/pkg1:amd64.list":         {Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg1:amd64.list")},
					"var/lib/dpkg/info/pkg2.list":               {Contents: featurefmt.LoadFileForTest("dpkg/testdata/pkg2.list")},
					"exec-me":                                   {Executable: true},
					"exec-me-2":                                 {Executable: true, ELFMetadata: &elf.Metadata{ImportedLibraries: []string{"gcc5.so.1"}}},
					"my-jar.jar":                                {Contents: []byte("jar contents")},
					"lib/linux/libgcc5.so.1":                    {ELFMetadata: &elf.Metadata{Sonames: []string{"gcc5.so.1"}}},
					"lib/linux/libsomelib.so.1":                 {ELFMetadata: &elf.Metadata{Sonames: []string{"somelib.so.1"}, ImportedLibraries: []string{"gcc5.so.1"}}},
				},
			),
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
