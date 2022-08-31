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

// Package alpinerelease implements a featurens.Detector for Alpine Linux based
// container image layers.
package alpinerelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/pkg/analyzer"
)

const (
	osName            = "alpine"
	alpineReleasePath = "etc/alpine-release"
	osReleasePath     = "etc/os-release"

	alpineEdgePrettyName = `PRETTY_NAME="Alpine Linux edge"`
)

var versionRegexp = regexp.MustCompile(`^(\d)+\.(\d)+\.(\d)+$`)

func init() {
	featurens.RegisterDetector("alpine-release", &detector{})
}

type detector struct{}

func (d detector) Detect(files analyzer.Files, _ *featurens.DetectorOptions) *database.Namespace {
	file, exists := files.Get(alpineReleasePath)
	if !exists {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(file.Contents)))
	for scanner.Scan() {
		line := scanner.Text()
		match := versionRegexp.FindStringSubmatch(line)
		if len(match) > 0 {
			versionNumbers := strings.Split(match[0], ".")
			return &database.Namespace{
				Name:          osName + ":" + "v" + versionNumbers[0] + "." + versionNumbers[1],
				VersionFormat: apk.ParserName,
			}
		}
	}

	// It is possible this is an alpine:edge image.
	// Verify this.
	file, exists = files.Get(osReleasePath)
	if !exists {
		return nil
	}
	scanner = bufio.NewScanner(strings.NewReader(string(file.Contents)))
	for scanner.Scan() {
		if scanner.Text() == alpineEdgePrettyName {
			return &database.Namespace{
				Name:          osName + ":edge",
				VersionFormat: apk.ParserName,
			}
		}
	}

	return nil
}

func (d detector) RequiredFilenames() []string {
	return []string{alpineReleasePath, osReleasePath}
}
