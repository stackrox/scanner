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
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
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

type componentMetadata struct {
	name          string
	version       string
	sourceName    string
	sourceVersion string
	arch          string
}

func (l lister) parseComponents(files tarutil.LayerFiles, file []byte, packagesMap map[featurefmt.PackageKey]*database.FeatureVersion, removedPackages set.StringSet, distroless bool) error {
	pkgFmt := `dpkg`
	if distroless {
		pkgFmt = `distroless`
	}
	defer metrics.ObserveListFeaturesTime(pkgFmt, "all", time.Now())

	scanner := bufio.NewScanner(bytes.NewReader(file))

	var pkgMetadata componentMetadata
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "": // Delimits end of package definition. Go to the bottom of the loop.
		case strings.HasPrefix(line, "Package: "):
			pkgMetadata.name = line[len("Package: "):]
			continue
		case strings.HasPrefix(line, "Version: "):
			version := line[len("Version: "):]
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithFields(map[string]interface{}{"name": pkgMetadata.name, "version": version}).Warning("could not parse package version. skipping")
				continue
			}
			pkgMetadata.version = version
			continue
		case strings.HasPrefix(line, "Architecture: "):
			pkgMetadata.arch = line[len("Architecture: "):]
			continue
		case strings.HasPrefix(line, "Status: "):
			if strings.Contains(line, "deinstall") {
				// It is assumed the package's name has already been determined at this point.
				removedPackages.Add(pkgMetadata.name)
			}
			continue
		case strings.HasPrefix(line, "Source: "):
			md := make(map[string]string)

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line[len("Source: "):], -1)[0]
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkgMetadata.sourceName = md["name"]
			// It is assumed the version has already been determined at this point.
			pkgMetadata.sourceVersion = pkgMetadata.version

			if md["version"] != "" {
				version := md["version"]
				err := versionfmt.Valid(dpkg.ParserName, version)
				if err != nil {
					log.WithError(err).WithFields(log.Fields{"name": pkgMetadata.name, "source name": pkgMetadata.sourceName, "version": version}).Warning("could not parse source package version. skipping")
					continue
				}

				pkgMetadata.sourceVersion = version
			}

			continue
		default:
			// We do not care about the other fields at this time.
			continue
		}

		// We must only be here if we are on an empty line, which delimits the end of a package.
		utils.Must(func() error {
			if line == "" {
				return nil
			}
			return errors.New("must not be here unless there is a programming error")
		}())

		handleComponent(files, &pkgMetadata, packagesMap, removedPackages, distroless)

		pkgMetadata = componentMetadata{}
	}

	return scanner.Err()
}

func handleComponent(files tarutil.LayerFiles, pkgMetadata *componentMetadata, packagesMap map[featurefmt.PackageKey]*database.FeatureVersion, removedPackages set.StringSet, distroless bool) {
	// Debian and Ubuntu vulnerability feeds only have entries for source packages,
	// and not the package binaries, though usually only the binaries are installed.
	pkgName := stringutils.FirstNonEmpty(pkgMetadata.sourceName, pkgMetadata.name)
	pkgVersion := stringutils.FirstNonEmpty(pkgMetadata.sourceVersion, pkgMetadata.version)

	// Sanity check the package definition.
	if pkgName == "" || pkgVersion == "" || removedPackages.Contains(pkgMetadata.name) {
		return
	}

	execToDeps := make(database.StringToStringsMap)
	libToDeps := make(database.StringToStringsMap)
	// Distroless containers do not provide executable files the same way distro containers do.
	if !distroless {
		// for example: var/lib/dpkg/info/vim.list
		filenamesList := dpkgInfoPrefix + pkgMetadata.name + dpkgFilenamesSuffix
		// for example: /var/lib/dpkg/info/zlib1g:amd64.list
		filenamesArchList := dpkgInfoPrefix + pkgMetadata.name + ":" + pkgMetadata.arch + dpkgFilenamesSuffix

		// Read the list of files provided by the current package.
		filenamesFileData, hasFile := files.Get(filenamesList)
		if !hasFile || len(filenamesFileData.Contents) == 0 {
			filenamesFileData, _ = files.Get(filenamesArchList)
		}

		filenamesFileScanner := bufio.NewScanner(bytes.NewReader(filenamesFileData.Contents))
		for filenamesFileScanner.Scan() {
			filename := filenamesFileScanner.Text()

			// The first character is always "/", which is removed when inserted into the layer files.
			fileData, hasFile := files.Get(filename[1:])
			if hasFile {
				featurefmt.AddToDependencyMap(filename, fileData, execToDeps, libToDeps)
			}
		}
		if err := filenamesFileScanner.Err(); err != nil {
			log.WithError(err).WithFields(log.Fields{"name": pkgMetadata.name, "version": pkgMetadata.version}).Warning("could not parse provided file list")
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
		feature.ExecutableToDependencies.Merge(execToDeps)
		feature.LibraryToDependencies.Merge(libToDeps)
		return
	}

	if len(libToDeps) == 0 {
		libToDeps = nil
	}
	if len(execToDeps) == 0 {
		execToDeps = nil
	}

	packagesMap[key] = &database.FeatureVersion{
		Feature: database.Feature{
			Name: pkgName,
		},
		Version:                  pkgVersion,
		ExecutableToDependencies: execToDeps,
		LibraryToDependencies:    libToDeps,
	}
}

func (l lister) ListFeatures(files tarutil.LayerFiles) ([]database.FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[featurefmt.PackageKey]*database.FeatureVersion)
	// Create a set to store removed packages to ensure it holds between files.
	// TODO: This may not be needed cross-file...
	removedPackages := set.NewStringSet()
	// For general images using dpkg.
	if f, hasFile := files.Get(statusFile); hasFile {
		if err := l.parseComponents(files, f.Contents, packagesMap, removedPackages, false); err != nil {
			return []database.FeatureVersion{}, errors.Wrapf(err, "parsing %s", statusFile)
		}
	}

	for filename, file := range files.GetFilesMap() {
		// For distroless images, which are based on Debian, but also useful for
		// all images using dpkg.
		// The var/lib/dpkg/status.d directory holds the files which define packages.
		if strings.HasPrefix(filename, statusDir) && filename != statusDir {
			if err := l.parseComponents(files, append(file.Contents, '\n'), packagesMap, removedPackages, true); err != nil {
				return []database.FeatureVersion{}, errors.Wrapf(err, "parsing %s", filename)
			}
		}
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		if !removedPackages.Contains(pkg.Feature.Name) {
			packages = append(packages, *pkg)
		}
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{statusFile}
}
