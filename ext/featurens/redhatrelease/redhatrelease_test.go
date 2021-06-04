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

package redhatrelease

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func TestDetector(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "amzn:2", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/system-release": []byte(`Amazon Linux release 2 (Karoo)`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "amzn:2018.03", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/system-release": []byte(`Amazon Linux AMI release 2018.03`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:6", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/oracle-release": []byte(`Oracle Linux Server release 6.8`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:7", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/oracle-release": []byte(`Oracle Linux Server release 7.2`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:6", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/centos-release": []byte(`CentOS release 6.6 (Final)`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "rhel:7", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/redhat-release": []byte(`Red Hat Enterprise Linux Server release 7.2 (Maipo)`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "rhel:8", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/redhat-release": []byte(`Red Hat Enterprise Linux release 8.0 (Ootpa)`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:8", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/redhat-release": []byte(`Red Hat Enterprise Linux release 8.0 (Ootpa)`),
			},
			Options: &featurens.DetectorOptions{UncertifiedRHEL: true},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:8", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/redhat-release": []byte(`CentOS Linux release 8.3.2011`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:7", VersionFormat: rpm.ParserName},
			Files: tarutil.FilesMap{
				"etc/system-release": []byte(`CentOS Linux release 7.1.1503 (Core)`),
			},
		},
		{
			ExpectedNamespace: nil,
			Files:             tarutil.FilesMap{},
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
