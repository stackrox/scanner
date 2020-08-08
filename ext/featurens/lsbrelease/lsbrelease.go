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

// Package lsbrelease implements a featurens.Detector for container image
// layers containing an lsb-release file.
//
// This detector is necessary for detecting Ubuntu Precise.
package lsbrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/featurens/util"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/tarutil"
)

var (
	lsbReleaseOSRegexp      = regexp.MustCompile(`^DISTRIB_ID=(.*)`)
	lsbReleaseVersionRegexp = regexp.MustCompile(`^DISTRIB_RELEASE=(.*)`)
)

type detector struct{}

func init() {
	featurens.RegisterDetector("lsb-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) *database.Namespace {
	f, hasFile := files["etc/lsb-release"]
	if !hasFile {
		return nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		r := lsbReleaseOSRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
		}

		r = lsbReleaseVersionRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)

			// We care about the .04 for Ubuntu but not for Debian / CentOS
			if OS == "centos" || OS == "debian" {
				i := strings.Index(version, ".")
				if i >= 0 {
					version = version[:i]
				}
			}
		}
	}

	OS = util.NormalizeOSName(OS)

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

func (d *detector) RequiredFilenames() []string {
	return []string{"etc/lsb-release"}
}
