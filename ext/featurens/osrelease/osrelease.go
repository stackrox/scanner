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

// Package osrelease implements a featurens.Detector for container image
// layers containing an os-release file.
//
// This detector is typically useful for detecting Debian or Ubuntu.
package osrelease

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/osrelease"
	"github.com/stackrox/scanner/pkg/tarutil"
)

var (
	// blacklistFilenames are files that should exclude this detector.
	blacklistFilenames = []string{
		"etc/oracle-release",
		"etc/redhat-release",
		"usr/lib/centos-release",
	}
)

type detector struct{}

func init() {
	featurens.RegisterDetector("os-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap, _ *featurens.DetectorOptions) *database.Namespace {
	var OS, version string

	for _, filePath := range blacklistFilenames {
		if _, hasFile := files[filePath]; hasFile {
			return nil
		}
	}

	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		OS, version = osrelease.GetIDFromOSRelease(f)
	}

	// Determine the VersionFormat.
	var versionFormat string
	switch OS {
	case "debian", "ubuntu":
		versionFormat = dpkg.ParserName
	case "centos", "rhel", "fedora", "amzn", "oracle":
		versionFormat = rpm.ParserName
	default:
		return nil
	}

	if OS != "" && version != "" {
		return &database.Namespace{
			Name:          OS + ":" + version,
			VersionFormat: versionFormat,
		}
	}
	return nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/os-release", "usr/lib/os-release"}
}
