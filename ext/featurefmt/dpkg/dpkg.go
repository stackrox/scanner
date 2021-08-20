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

// Package dpkg implements a featurefmt.Lister for dpkg packages.
package dpkg

import (
	"bufio"
	"bytes"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/metrics"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	statusFile = "var/lib/dpkg/status"
	statusDir  = "var/lib/dpkg/status.d"

	dpkgInfoPrefix      = "var/lib/dpkg/info/"
	dpkgFilenamesSuffix = ".list"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`(?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()

	// FilenamesListRegexp is the pattern for dpkg files which list the filenames the
	// related package provides.
	FilenamesListRegexp = regexp.MustCompile(`^var/lib/dpkg/info/(.*)\.list$`)
)

type lister struct{}

func init() {
	featurefmt.RegisterLister("dpkg", &lister{})
}

///////////////////////////////////////////////////
// BEGIN
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

func (l lister) parseComponent(files tarutil.FilesMap, file []byte, packagesMap map[featurefmt.PackageKey]*database.FeatureVersion, removedPackages set.StringSet, distroless bool) error {
	pkgFmt := `dpkg`
	if distroless {
		pkgFmt = `distroless`
	}
	defer metrics.ObserveListFeaturesTime(pkgFmt, "all", time.Now())

	// The database is actually an RFC822-like message with "\n\n"
	// separators, so don't be alarmed by the usage of the "net/mail"
	// package here.
	scanner := bufio.NewScanner(bytes.NewReader(file))
	scanner.Split(dbSplitFunc)
	for scanner.Scan() {
		msg, err := mail.ReadMessage(bytes.NewReader(scanner.Bytes()))
		if err != nil {
			log.WithError(err).Warning("could not parse dpkg db entry. skipping")
			continue
		}

		currPkgName := msg.Header.Get("Package")

		if strings.Contains(msg.Header.Get("Status"), "deinstall") {
			// This package is meant to be uninstalled, so ignore it.
			removedPackages.Add(currPkgName)
			continue
		}

		currPkgVersion := msg.Header.Get("Version")
		err = versionfmt.Valid(dpkg.ParserName, currPkgVersion)
		if err != nil {
			log.WithError(err).WithFields(map[string]interface{}{"name": currPkgName, "version": currPkgVersion}).Warning("could not parse package version. skipping")
			continue
		}

		var sourceName, sourceVersion string

		// Get the package's source, if it exists.
		if src := msg.Header.Get("Source"); src != "" {
			md := make(map[string]string)

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(src, -1)[0]
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			sourceName = md["name"]
			sourceVersion = currPkgVersion

			if md["version"] != "" {
				version := md["version"]
				err = versionfmt.Valid(dpkg.ParserName, version)
				if err != nil {
					log.WithError(err).WithFields(log.Fields{"name": sourceName, "version": version}).Warning("could not parse source package version. skipping")
					continue
				}

				sourceVersion = version
			}
		}

		// Debian and Ubuntu vulnerability feeds only have entries for source packages,
		// and not the package binaries, though usually only the binaries are installed.
		pkgName := sourceName
		pkgVersion := sourceVersion
		if pkgName == "" {
			pkgName = currPkgName
			pkgVersion = currPkgVersion
		}

		var executables []string
		// Distroless containers do not provide executable files the same way distro containers do.
		if !distroless && features.ActiveVulnMgmt.Enabled() {
			// for example: var/lib/dpkg/info/vim.list
			filenamesList := dpkgInfoPrefix + currPkgName + dpkgFilenamesSuffix
			arch := msg.Header.Get("Architecture")
			// for example: /var/lib/dpkg/info/zlib1g:amd64.list
			filenamesArchList := dpkgInfoPrefix + currPkgName + ":" + arch + dpkgFilenamesSuffix

			// Read the list of files provided by the current package.
			filenamesFileData := files[filenamesList]
			if len(filenamesFileData.Contents) == 0 {
				filenamesFileData = files[filenamesArchList]
			}

			filenamesFileScanner := bufio.NewScanner(bytes.NewReader(filenamesFileData.Contents))
			for filenamesFileScanner.Scan() {
				filename := filenamesFileScanner.Text()

				// The first character is always "/", which is removed when inserted into the files maps.
				if fileData := files[filename[1:]]; fileData.Executable {
					executables = append(executables, filename)
				}
			}
			if err := filenamesFileScanner.Err(); err != nil {
				log.WithError(err).WithFields(log.Fields{"name": currPkgName, "version": currPkgVersion}).Warning("could not parse provided file list")
				// Even though there is an error, do not skip the package.
				// The active vulnerability management analysis may be incomplete, but that should not prevent us from
				// performing typical vulnerability management analysis.
			}
		}

		key := featurefmt.PackageKey{
			Name:    pkgName,
			Version: pkgVersion,
		}

		// If the package already exists, then this must be a source package
		// with multiple associated packages.
		if feature, exists := packagesMap[key]; exists {
			// Append the executable files for the associated package to the source package.
			feature.ProvidedExecutables = append(feature.ProvidedExecutables, executables...)
			continue
		}

		packagesMap[key] = &database.FeatureVersion{
			Feature: database.Feature{
				Name: pkgName,
			},
			Version:             pkgVersion,
			ProvidedExecutables: executables,
		}
	}

	return scanner.Err()
}

// dbSplitFunc is a bufio.SplitFunc that looks for a double-newline and leaves it
// attached to the resulting token.
func dbSplitFunc(data []byte, atEOF bool) (int, []byte, error) {
	const delim = "\n\n"
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte(delim)); i >= 0 {
		return i + len(delim), data[:i+len(delim)], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

///////////////////////////////////////////////////
// END
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[featurefmt.PackageKey]*database.FeatureVersion)
	// Create a set to store removed packages to ensure it holds between files.
	// TODO: This may not be needed cross-file...
	removedPackages := set.NewStringSet()
	// For general images using dpkg.
	if f, hasFile := files[statusFile]; hasFile {
		if err := l.parseComponent(files, f.Contents, packagesMap, removedPackages, false); err != nil {
			return []database.FeatureVersion{}, errors.Wrapf(err, "parsing %s", statusFile)
		}
	}

	for filename, file := range files {
		// For distroless images, which are based on Debian, but also useful for
		// all images using dpkg.
		if strings.HasPrefix(filename, statusDir) {
			if err := l.parseComponent(files, append(file.Contents, '\n'), packagesMap, removedPackages, true); err != nil {
				return []database.FeatureVersion{}, errors.Wrapf(err, "parsing %s", filename)
			}
		}
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		if !removedPackages.Contains(pkg.Feature.Name) {
			// Sort the provided executables and only allow unique executables.
			sort.Strings(pkg.ProvidedExecutables)
			filtered := pkg.ProvidedExecutables[:0]
			prev := ""
			for _, executable := range pkg.ProvidedExecutables {
				if executable != prev {
					filtered = append(filtered, executable)
				}
				prev = executable
			}
			pkg.ProvidedExecutables = filtered

			packages = append(packages, *pkg)
		}
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{statusFile}
}
