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

package apk

import (
	"testing"

	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestAPKFeatureDetection(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "false")
	defer env.RestoreAll()

	testData := []featurefmt.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "musl"},
					Version: "1.1.14-r10",
				},
				{
					Feature: database.Feature{Name: "busybox"},
					Version: "1.24.2-r9",
				},
				{
					Feature: database.Feature{Name: "alpine-baselayout"},
					Version: "3.0.3-r0",
				},
				{
					Feature: database.Feature{Name: "alpine-keys"},
					Version: "1.1-r0",
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: "1.2.8-r2",
				},
				{
					Feature: database.Feature{Name: "libcrypto1.0"},
					Version: "1.0.2h-r1",
				},
				{
					Feature: database.Feature{Name: "libssl1.0"},
					Version: "1.0.2h-r1",
				},
				{
					Feature: database.Feature{Name: "apk-tools"},
					Version: "2.6.7-r0",
				},
				{
					Feature: database.Feature{Name: "scanelf"},
					Version: "1.1.6-r0",
				},
				{
					Feature: database.Feature{Name: "musl-utils"},
					Version: "1.1.14-r10",
				},
				{
					Feature: database.Feature{Name: "libc-utils"},
					Version: "0.7-r0",
				},
			},
			Files: tarutil.FilesMap{
				"lib/apk/db/installed": tarutil.FileData{Contents: featurefmt.LoadFileForTest("apk/testdata/installed")},
			},
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}

func TestAPKFeatureDetectionWithActiveVulnMgmt(t *testing.T) {
	env := envisolator.NewEnvIsolator(t)
	env.Setenv(features.ActiveVulnMgmt.EnvVar(), "true")
	defer env.RestoreAll()

	testData := []featurefmt.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "musl"},
					Version: "1.1.14-r10",
					ProvidedExecutables: []string{
						"/lib/ld-musl-x86_64.so.1",
						"/lib/libc.musl-x86_64.so.1",
					},
				},
				{
					Feature: database.Feature{Name: "busybox"},
					Version: "1.24.2-r9",
					ProvidedExecutables: []string{
						"/bin/busybox",
					},
				},
				{
					Feature: database.Feature{Name: "alpine-baselayout"},
					Version: "3.0.3-r0",
					ProvidedExecutables: []string{
						"/etc/crontabs/root",
						"/etc/hosts",
					},
				},
				{
					Feature: database.Feature{Name: "alpine-keys"},
					Version: "1.1-r0",
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: "1.2.8-r2",
				},
				{
					Feature: database.Feature{Name: "libcrypto1.0"},
					Version: "1.0.2h-r1",
				},
				{
					Feature: database.Feature{Name: "libssl1.0"},
					Version: "1.0.2h-r1",
				},
				{
					Feature: database.Feature{Name: "apk-tools"},
					Version: "2.6.7-r0",
				},
				{
					Feature: database.Feature{Name: "scanelf"},
					Version: "1.1.6-r0",
				},
				{
					Feature: database.Feature{Name: "musl-utils"},
					Version: "1.1.14-r10",
				},
				{
					Feature: database.Feature{Name: "libc-utils"},
					Version: "0.7-r0",
				},
			},
			Files: tarutil.FilesMap{
				"lib/apk/db/installed":      tarutil.FileData{Contents: featurefmt.LoadFileForTest("apk/testdata/installed")},
				"lib/libc.musl-x86_64.so.1": tarutil.FileData{Executable: true},
				"lib/ld-musl-x86_64.so.1":   tarutil.FileData{Executable: true},
				"bin/busybox":               tarutil.FileData{Executable: true},
				"etc/hosts":                 tarutil.FileData{Executable: true},
				"etc/crontabs/root":         tarutil.FileData{Executable: true},
			},
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}
