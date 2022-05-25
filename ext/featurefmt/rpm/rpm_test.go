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

package rpm

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/elf"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestRpmFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		// Test a CentOS 7 RPM database
		// Memo: Use the following command on a RPM-based system to shrink a database: rpm -qa --qf "%{NAME}\n" |tail -n +3| xargs rpm -e --justdb
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear once
				{
					Feature: database.Feature{Name: "centos-release"},
					Version: "7-1.1503.el7.centos.2.8",
				},
				// Two packages from this source are installed, it should only appear once
				{
					Feature: database.Feature{Name: "filesystem"},
					Version: "3.2-18.el7",
					ExecutableToDependencies: database.StringToStringsMap{
						"/usr/games":     {"base.so.1": {}, "mock.so.1.0": {}},
						"/usr/include":   {},
						"/usr/lib/debug": {},
					},
				},
				{
					Feature: database.Feature{Name: "libmock"},
					Version: "0.0.1-el7",
					ExecutableToDependencies: database.StringToStringsMap{
						"/usr/bin/mock_exec": {},
					},
					LibraryToDependencies: database.StringToStringsMap{
						"base.so.1":   {},
						"mock.so.1":   {"base.so.1": {}},
						"mock.so.1.0": {"base.so.1": {}},
					},
				},
			},
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"var/lib/rpm/Packages":   {Contents: featurefmt.LoadFileForTest("rpm/testdata/Packages")},
				"etc/centos-release":     {Executable: true},
				"usr/games":              {Executable: true, ELFMetadata: &elf.Metadata{ImportedLibraries: []string{"base.so.1", "mock.so.1.0"}}},
				"usr/include":            {Executable: true},
				"usr/lib/debug":          {Executable: true},
				"usr/bin/mock_exec":      {Executable: true, ELFMetadata: &elf.Metadata{Sonames: []string{}}},
				"usr/lib64/libmock.so.1": {ELFMetadata: &elf.Metadata{Sonames: []string{"mock.so.1", "mock.so.1.0"}, ImportedLibraries: []string{"base.so.1"}}},
				"usr/lib64/libbase.so.1": {ELFMetadata: &elf.Metadata{Sonames: []string{"base.so.1"}}},
			}),
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
