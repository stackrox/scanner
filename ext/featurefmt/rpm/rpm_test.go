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

	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/elf"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestRpmFeatureDetection(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "false")
	defer env.RestoreAll()

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
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/rpm/Packages": tarutil.FileData{Contents: featurefmt.LoadFileForTest("rpm/testdata/Packages")},
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}

func TestRpmFeatureDetectionWithActiveVulnMgmt(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "true")
	defer env.RestoreAll()

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
						"/usr/games":     {"ld-linux.so.2": {}, "libc.so.6.1": {}},
						"/usr/include":   {},
						"/usr/lib/debug": {},
					},
				},
				{
					Feature: database.Feature{Name: "glibc"},
					Version: "2.28-72.el8_1.1.x86_64",
					ExecutableToDependencies: database.StringToStringsMap{
						"/sbin/ldconfig": {},
					},
					LibraryToDependencies: database.StringToStringsMap{
						"libc.so.6":     {"ld-linux.so.2": {}},
						"libc.so.6.1":   {"ld-linux.so.2": {}},
						"ld-linux.so.2": {},
					},
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/rpm/Packages":       tarutil.FileData{Contents: featurefmt.LoadFileForTest("rpm/testdata/Packages")},
				"etc/centos-release":         tarutil.FileData{Executable: true},
				"usr/games":                  tarutil.FileData{Executable: true, ELFMetadata: &elf.Metadata{ImportedLibraries: []string{"ld-linux.so.2", "libc.so.6.1"}}},
				"usr/include":                tarutil.FileData{Executable: true},
				"usr/lib/debug":              tarutil.FileData{Executable: true},
				"lib64/libc.so.6":            tarutil.FileData{ELFMetadata: &elf.Metadata{Sonames: []string{"libc.so.6", "libc.so.6.1"}, ImportedLibraries: []string{"ld-linux.so.2"}}},
				"sbin/ldconfig":              tarutil.FileData{Executable: true, ELFMetadata: &elf.Metadata{Sonames: []string{}}},
				"lib64/ld-linux-x86-64.so.2": tarutil.FileData{ELFMetadata: &elf.Metadata{Sonames: []string{"ld-linux.so.2"}}},
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
