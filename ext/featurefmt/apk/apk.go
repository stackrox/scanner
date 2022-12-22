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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/metrics"
)

const (
	dbPath = "lib/apk/db/installed"
)

func init() {
	featurefmt.RegisterLister("apk", &lister{})
}

type lister struct{}

func (l lister) ListFeatures(files analyzer.Files) ([]database.FeatureVersion, error) {
	file, exists := files.Get(dbPath)
	if !exists {
		return []database.FeatureVersion{}, nil
	}

	defer metrics.ObserveListFeaturesTime("apk", "all", time.Now())

	// Iterate over each line in the "installed" file attempting to parse each
	// package into a feature that will be stored in a set to guarantee
	// uniqueness.
	pkgSet := make(map[featurefmt.PackageKey]database.FeatureVersion)
	var pkg database.FeatureVersion
	// Use map to ensures only unique executables or libraries are stored per package.
	execToDeps := make(database.StringToStringsMap)
	libToDeps := make(database.StringToStringsMap)
	scanner := bufio.NewScanner(bytes.NewBuffer(file.Contents))
	var dir string
	var source string

	for scanner.Scan() {
		line := scanner.Text()
		// Parse the package name or version.
		// See https://wiki.alpinelinux.org/wiki/Apk_spec#Syntax for more information.
		switch {
		case line == "":
			// Reached end of package definition.

			// Protect the map from entries with invalid versions.
			if pkg.Feature.Name != "" && pkg.Version != "" {
				if len(execToDeps) != 0 {
					pkg.ExecutableToDependencies = execToDeps
				}
				if len(libToDeps) != 0 {
					pkg.LibraryToDependencies = libToDeps
				}
				if source != "" {
					pkg.Feature.Name = source
					source = ""
				}

				key := featurefmt.PackageKey{
					Name:    pkg.Feature.Name,
					Version: pkg.Version,
				}
				if oldPkg, exists := pkgSet[key]; exists {
					pkg.ExecutableToDependencies.Merge(oldPkg.ExecutableToDependencies)
					pkg.LibraryToDependencies.Merge(oldPkg.LibraryToDependencies)
				}

				pkgSet[key] = pkg
			}

			pkg = database.FeatureVersion{}
			execToDeps = make(database.StringToStringsMap)
			libToDeps = make(database.StringToStringsMap)
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
		case line[:2] == "F:":
			dir = line[2:]
		case line[:2] == "o:":
			source = line[2:]
		case line[:2] == "R:":
			filename := fmt.Sprintf("/%s/%s", dir, line[2:])
			// The first character is always "/", which is removed when inserted into the layer files.
			fileData, hasFile := files.Get(filename[1:])
			if hasFile {
				featurefmt.AddToDependencyMap(filename, fileData, execToDeps, libToDeps)
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
