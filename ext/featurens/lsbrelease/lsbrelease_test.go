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

package lsbrelease

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDetector(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "ubuntu:12.04", VersionFormat: dpkg.ParserName},
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/lsb-release": {
					Contents: []byte(
						`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
DISTRIB_DESCRIPTION="Ubuntu 12.04 LTS"`),
				},
			}),
		},
		{ // We don't care about the minor version of Debian
			ExpectedNamespace: &database.Namespace{Name: "debian:7", VersionFormat: dpkg.ParserName},
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/lsb-release": {
					Contents: []byte(
						`DISTRIB_ID=Debian
DISTRIB_RELEASE=7.1
DISTRIB_CODENAME=wheezy
DISTRIB_DESCRIPTION="Debian 7.1"`),
				},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files:             tarutil.LayerFiles{},
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
