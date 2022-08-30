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

package alpinerelease

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDetector(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v3.3", VersionFormat: apk.ParserName},
			Files:             tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{"etc/alpine-release": {Contents: []byte(`3.3.4`)}}),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v3.4", VersionFormat: apk.ParserName},
			Files:             tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{"etc/alpine-release": {Contents: []byte(`3.4.0`)}}),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v0.3", VersionFormat: apk.ParserName},
			Files:             tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{"etc/alpine-release": {Contents: []byte(`0.3.4`)}}),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v0.3", VersionFormat: apk.ParserName},
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{"etc/alpine-release": {Contents: []byte(`
0.3.4
`)}}),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:edge", VersionFormat: apk.ParserName},
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/alpine-release": {Contents: []byte(`3.14.0_alpha20210212`)},
				"etc/os-release": {Contents: []byte(
					`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.14.0_alpha20210212
PRETTY_NAME="Alpine Linux edge"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files:             tarutil.CreateNewLayerFiles(nil),
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
