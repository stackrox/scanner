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
				"var/lib/rpm/Packages": &tarutil.FileData{Contents: featurefmt.LoadFileForTest("rpm/testdata/Packages")},
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
					ProvidedExecutables: []string{
						"/usr/games",
						"/usr/include",
						"/usr/lib/debug",
					},
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/rpm/Packages": &tarutil.FileData{Contents: featurefmt.LoadFileForTest("rpm/testdata/Packages")},
				"etc/centos-release":   nil,
				"usr/games":            nil,
				"usr/include":          nil,
				"usr/lib/debug":        nil,
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
