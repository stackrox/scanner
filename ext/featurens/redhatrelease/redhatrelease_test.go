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
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/system-release": {Contents: []byte(`Amazon Linux release 2 (Karoo)`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "amzn:2018.03", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/system-release": {Contents: []byte(`Amazon Linux AMI release 2018.03`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:6", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/oracle-release": {Contents: []byte(`Oracle Linux Server release 6.8`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:7", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/oracle-release": {Contents: []byte(`Oracle Linux Server release 7.2`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:6", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/centos-release": {Contents: []byte(`CentOS release 6.6 (Final)`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "rhel:7", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/redhat-release": {Contents: []byte(`Red Hat Enterprise Linux Server release 7.2 (Maipo)`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "rhel:8", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/redhat-release": {Contents: []byte(`Red Hat Enterprise Linux release 8.0 (Ootpa)`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:8", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/redhat-release": {Contents: []byte(`Red Hat Enterprise Linux release 8.0 (Ootpa)`)},
			}, nil, nil),
			Options: &featurens.DetectorOptions{UncertifiedRHEL: true},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:8", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/redhat-release": {Contents: []byte(`CentOS Linux release 8.3.2011`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:7", VersionFormat: rpm.ParserName},
			Files: tarutil.CreateNewFilesMap(map[string]tarutil.FileData{
				"etc/system-release": {Contents: []byte(`CentOS Linux release 7.1.1503 (Core)`)},
			}, nil, nil),
		},
		{
			ExpectedNamespace: nil,
			Files:             tarutil.CreateNewFilesMap(nil, nil, nil),
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
