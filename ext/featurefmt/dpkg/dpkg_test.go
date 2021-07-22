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
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDpkgFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		// Test an Ubuntu dpkg status file
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear one time
				{
					Feature:             database.Feature{Name: "pam"},
					Version:             "1.1.8-3.1ubuntu3",
					ProvidedExecutables: []string{"/test/executable"},
				},
				{
					Feature: database.Feature{Name: "makedev"}, // The source name and the package name are equals
					Version: "2.3.1-93ubuntu1",                 // The version comes from the "Version:" line
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
			},
			Files: tarutil.FilesMap{
				"var/lib/dpkg/status":                featurefmt.LoadFileForTest("dpkg/testdata/status"),
				"var/lib/dpkg/status.d/base":         featurefmt.LoadFileForTest("dpkg/testdata/statusd-base"),
				"var/lib/dpkg/status.d/netbase":      featurefmt.LoadFileForTest("dpkg/testdata/statusd-netbase"),
				"var/lib/dpkg/info/pam.list":         featurefmt.LoadFileForTest("dpkg/testdata/pam.list"),
				"var/lib/dpkg/info/gcc-5:amd64.list": featurefmt.LoadFileForTest("dpkg/testdata/gcc-5:amd64.list"),
				"test/executable":                    nil,
				"i/am/an/executable":                 nil,
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
