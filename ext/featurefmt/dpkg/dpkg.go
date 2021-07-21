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
	"io"
	"net/mail"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	statusFile = "var/lib/dpkg/status"
	statusDir  = "var/lib/dpkg/status.d"

	dpkgInfoPrefix = "var/lib/dpkg/info/"
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


func (l lister) parseComponent(files tarutil.FilesMap, file []byte, packagesMap map[string]database.FeatureVersion) {
	// The database is actually an RFC822-like message with "\n\n"
	// separators, so don't be alarmed by the usage of the "net/mail"
	// package here.
	scanner := bufio.NewScanner(bytes.NewReader(file))
	scanner.Split(dbSplit)
	for scanner.Scan() {
		log.Info(scanner.Text())
		msg, err := mail.ReadMessage(bytes.NewReader(scanner.Bytes()))
		if err != nil {
			if err != io.EOF {
				log.WithError(err).Warning("could not parse dpkg db entry. skipping")
			}
			continue
		}
		log.Info("Howdy")

		// This package is meant to be uninstalled, so ignore it.
		if strings.Contains(msg.Header.Get("Status"), "deinstall") {
			continue
		}

		name := msg.Header.Get("Package")
		version := msg.Header.Get("Version")
		err = versionfmt.Valid(dpkg.ParserName, version)
		if err != nil {
			log.WithError(err).WithFields(map[string]interface{}{"name": name, "version": version}).Warning("could not parse package version. skipping")
			continue
		}

		if src := msg.Header.Get("Source"); src != "" {
			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(src, -1)[0]
			md := map[string]string{}

			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			name = md["name"]

			if md["version"] != "" {
				v := md["version"]
				err = versionfmt.Valid(dpkg.ParserName, v)
				if err != nil {
					log.WithError(err).WithField("version", v).Warning("could not parse package version. skipping")
					continue
				} else {
					version = v
				}
			}
		}

		key := name + "#" + version
		if _, exists := packagesMap[key]; exists {
			// No need to look through the executable files again.
			continue
		}

		var executables []string
		var filenames []byte
		// for example: var/lib/dpkg/info/vim.list
		if filenames = files[dpkgInfoPrefix + name + dpkgFilenamesSuffix]; len(filenames) == 0 {
			arch := msg.Header.Get("Architecture")
			// for example: /var/lib/dpkg/info/zlib1g:amd64.list
			filenames = files[dpkgInfoPrefix + name + ":" + arch + dpkgFilenamesSuffix]
		}

		filenameScanner := bufio.NewScanner(bytes.NewReader(filenames))
		for filenameScanner.Scan() {
			// The first character is always "/", which is removed when inserted into the files maps.
			filename := scanner.Text()[1:]

			// It is assumed if the listed file is tracked, it is an executable file.
			if _, exists := files[filename]; exists {
				executables = append(executables, filename)
			}
		}

		packagesMap[key] = database.FeatureVersion{
			Feature: database.Feature{
				Name:       name,
			},
			Version:             version,
			ProvidedExecutables: executables,
		}
	}

	//var pkg database.FeatureVersion
	//var currentPkgIsRemoved bool
	//var err error
	//scanner := bufio.NewScanner(bytes.NewReader(file))
	//for scanner.Scan() {
	//	line := scanner.Text()
	//
	//	if strings.HasPrefix(line, "Package: ") {
	//		// Package line
	//		// Defines the name of the package
	//		pkg.Feature.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
	//		pkg.Version = ""
	//	} else if strings.HasPrefix(line, "Source: ") {
	//		// Source line (Optional)
	//		// Gives the name of the source package
	//		// May also specifies a version
	//
	//		srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
	//		md := map[string]string{}
	//
	//		for i, n := range srcCapture {
	//			md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
	//		}
	//
	//		pkg.Feature.Name = md["name"]
	//
	//		if md["version"] != "" {
	//			version := md["version"]
	//			err = versionfmt.Valid(dpkg.ParserName, version)
	//
	//			if err != nil {
	//				log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
	//
	//			} else {
	//				pkg.Version = version
	//			}
	//		}
	//	} else if strings.HasPrefix(line, "Version: ") && pkg.Version == "" {
	//		// Version line
	//		// Defines the version of the package
	//		// This version is less important than a version retrieved from a Source line
	//		// because the Debian vulnerabilities often skips the epoch from the Version field
	//		// which is not present in the Source version, and because +bX revisions don't matter
	//		version := strings.TrimPrefix(line, "Version: ")
	//		err = versionfmt.Valid(dpkg.ParserName, version)
	//		if err != nil {
	//			log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
	//		} else {
	//			pkg.Version = version
	//		}
	//	} else if strings.HasPrefix(line, "Status: ") {
	//		currentPkgIsRemoved = strings.Contains(line, "deinstall")
	//	} else if line == "" {
	//		pkg = database.FeatureVersion{}
	//		currentPkgIsRemoved = false
	//	}
	//
	//	// Add the package to the result array if we have all the information
	//	if pkg.Feature.Name != "" && pkg.Version != "" {
	//		key := pkg.Feature.Name + "#" + pkg.Version
	//
	//		if !currentPkgIsRemoved {
	//			packagesMap[key] = pkg
	//		} else {
	//			removedPackages.Add(key)
	//		}
	//		pkg = database.FeatureVersion{}
	//		currentPkgIsRemoved = false
	//	}
	//}
}

// dbSplit is a bufio.SplitFunc that looks for a double-newline and leaves it
// attached to the resulting token.
func dbSplit(data []byte, atEOF bool) (int, []byte, error) {
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

func (l lister) parseFilenamesList(packageName string, file []byte, packagesMap map[string]database.FeatureVersion) {

}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)
	// For general images using dpkg.
	if f, hasFile := files[statusFile]; hasFile {
		l.parseComponent(files, f, packagesMap)
	}

	for filename, file := range files {
		// For distroless images, which are based on Debian, but also useful for
		// all images using dpkg.
		if strings.HasPrefix(filename, statusDir) {
			log.Info("Hello")
			l.parseComponent(files, file, packagesMap)
		}
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/dpkg/status"}
}
