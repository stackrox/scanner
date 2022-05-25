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

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/elf"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestAPKFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "musl"},
					Version: "1.1.14-r10",
					ExecutableToDependencies: database.StringToStringsMap{
						"/lib/ld-musl-x86_64.so.1":   {},
						"/lib/libc.musl-x86_64.so.1": {"ld.so.1": {}},
					},
					LibraryToDependencies: database.StringToStringsMap{
						"c.so.1":  {"ld.so.1": {}},
						"ld.so.1": {},
					},
				},
				{
					Feature: database.Feature{Name: "busybox"},
					Version: "1.24.2-r9",
					ExecutableToDependencies: database.StringToStringsMap{
						"/bin/busybox": {"c.so.1": {}, "ld.so.1": {}},
					},
				},
				{
					Feature: database.Feature{Name: "alpine-baselayout"},
					Version: "3.0.3-r0",
					ExecutableToDependencies: database.StringToStringsMap{
						"/etc/crontabs/root": {},
						"/etc/hosts":         {},
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
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"lib/apk/db/installed":      {Contents: featurefmt.LoadFileForTest("apk/testdata/installed")},
				"lib/libc.musl-x86_64.so.1": {Executable: true, ELFMetadata: &elf.Metadata{Sonames: []string{"c.so.1"}, ImportedLibraries: []string{"ld.so.1"}}},
				"lib/ld-musl-x86_64.so.1":   {Executable: true, ELFMetadata: &elf.Metadata{Sonames: []string{"ld.so.1"}}},
				"bin/busybox":               {Executable: true, ELFMetadata: &elf.Metadata{Sonames: []string{}, ImportedLibraries: []string{"c.so.1", "ld.so.1"}}},
				"etc/hosts":                 {Executable: true},
				"etc/crontabs/root":         {Executable: true},
			}),
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}
