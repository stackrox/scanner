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

// Package apk implements a featurefmt.Lister for APK packages.
package apk

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	dbPath = "lib/apk/db/installed"
)

func init() {
	featurefmt.RegisterLister("apk", &lister{})
}

type lister struct{}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	file, exists := files[dbPath]
	if !exists {
		return []database.FeatureVersion{}, nil
	}

	// Iterate over each line in the "installed" file attempting to parse each
	// package into a feature that will be stored in a set to guarantee
	// uniqueness.
	pkgSet := make(map[featurefmt.PackageKey]database.FeatureVersion)
	var pkg database.FeatureVersion
	// executablesSet ensures only unique executables are stored per package.
	executablesSet := set.NewStringSet()
	scanner := bufio.NewScanner(bytes.NewBuffer(file.Contents))
	var dir string
	for scanner.Scan() {
		line := scanner.Text()
		// Parse the package name or version.
		// See https://wiki.alpinelinux.org/wiki/Apk_spec#Syntax for more information.
		switch {
		case line == "":
			// Reached end of package definition.

			// Protect the map from entries with invalid versions.
			if pkg.Feature.Name != "" && pkg.Version != "" {
				executables := make([]string, 0, executablesSet.Cardinality())
				for executable := range executablesSet {
					executables = append(executables, executable)
				}
				sort.Strings(executables)
				pkg.ProvidedExecutables = append(pkg.ProvidedExecutables, executables...)

				key := featurefmt.PackageKey{
					Name:    pkg.Feature.Name,
					Version: pkg.Version,
				}
				pkgSet[key] = pkg
			}

			pkg = database.FeatureVersion{}
			executablesSet.Clear()
		case len(line) < 2:
			// Invalid line.
			continue
		case line[:2] == "P:":
			// Start of a package definition.
			pkg.Feature.Name = line[2:]
		case line[:2] == "V:":
			version := line[2:]
			err := versionfmt.Valid(apk.ParserName, version)
			if err != nil {
				// Assumes we already passed the "P:", as is expected in a well-formed alpine database.
				log.WithError(err).WithFields(log.Fields{"name": pkg.Feature.Name, "version": version}).Warning("could not parse package version; skipping")
				continue
			}

			pkg.Version = version
		case line[:2] == "F:" && features.ActiveVulnMgmt.Enabled():
			dir = line[2:]
		case line[:2] == "R:" && features.ActiveVulnMgmt.Enabled():
			filename := fmt.Sprintf("/%s/%s", dir, line[2:])
			// The first character is always "/", which is removed when inserted into the files maps.
			if fileData := files[filename[1:]]; fileData.Executable {
				pkg.ProvidedExecutables = append(pkg.ProvidedExecutables, filename)
			}
		}
	}

	// Convert the map into a slice.
	pkgs := make([]database.FeatureVersion, 0, len(pkgSet))
	for _, pkg := range pkgSet {
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{dbPath}
}
