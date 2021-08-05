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

// Package rpm implements a featurefmt.Lister for rpm packages.
package rpm

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/stackrox/rox/pkg/utils"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	dbPath = "var/lib/rpm/Packages"

	queryFmt = `%{name}\n` +
		`%{evr}\n` +
		`[%{FILENAMES}\n]` +
		`.\n`
)

type lister struct{}

func init() {
	featurefmt.RegisterLister("rpm", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	f, hasFile := files[dbPath]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[featurefmt.PackageKey]database.FeatureVersion)

	// Write the required "Packages" file to disk
	tmpDir, err := os.MkdirTemp("", "rpm")
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for RPM detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	err = os.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for RPM detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	// Extract binary package names because RHSA refers to binary package names.
	cmd := exec.Command("rpm", "--dbpath", tmpDir, "-qa", "--qf", queryFmt)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return []database.FeatureVersion{}, errors.Wrap(err, "Unable to get pipe for RPM command")
	}
	defer utils.IgnoreError(r.Close)

	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf

	if err := cmd.Start(); err != nil {
		return []database.FeatureVersion{}, errors.Wrap(err, "Could not query RPM: either the DB is corrupted or FIPs mode is enabled")
	}

	features, err := parseFeatures(r, files)

	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not query RPM: either the DB is corrupted or FIPs mode is enabled")
		// Bubble up because this may be fixable by using a different base image.
		return []database.FeatureVersion{}, errors.New("could not query RPM: either the DB is corrupted or FIPs mode is enabled")
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) != 2 {
			// We may see warnings on some RPM versions:
			// "warning: Generating 12 missing index(es), please wait..."
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if line[0] == "gpg-pubkey" {
			continue
		}

		// Parse version
		version := strings.Replace(line[1], "(none):", "", -1)
		err := versionfmt.Valid(rpm.ParserName, version)
		if err != nil {
			log.WithError(err).WithField("version", line[1]).Warning("could not parse package version. skipping")
			continue
		}

		// Add package
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: line[0],
			},
			Version: version,
		}
		key := featurefmt.PackageKey{
			Name:    pkg.Feature.Name,
			Version: pkg.Version,
		}
		packagesMap[key] = pkg
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func parseFeatures(r io.Reader, files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	var features []database.FeatureVersion

	fv := new(database.FeatureVersion)
	s := bufio.NewScanner(r)
	for i := 0; s.Scan(); i++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "(none)") {
			continue
		}

		if line == "." {
			// Reached feature delimiter.

			// Ensure the current feature is well-formed.
			// If it is, add it to the return slice.
			if fv.Name != "" && p.Version != "" && p.Arch != "" {
				if len(p.ProvidedExecutables) > 0 {
					fmt.Println(p, " ", p.ProvidedExecutables[0])
				}
				pkgs = append(pkgs, p)
			}

			// Start a new package definition and reset 'i'.
			p = new(database.RHELv2Package)
			i = -1
			continue
		}

		switch i {
		case 0:
			// This is not a real feature. Skip it...
			if line == "gpg-pubkey" {
				continue
			}
			fv.Feature.Name = line
		case 1:
			fv.Version = line
		default:
			// i >= 2 is reserved for provided filenames.

			// Rename to make it clear what the line represents.
			filename := line
			// The first character is always "/", which is removed when inserted into the files maps.
			// It is assumed if the listed file is tracked, it is an executable file.
			if _, exists := files[filename[1:]]; exists && filename[1:] != dbPath {
				fv.ProvidedExecutables = append(fv.ProvidedExecutables, filename)
			}
		}
	}

	return features, s.Err()
}

func (l lister) RequiredFilenames() []string {
	return []string{dbPath}
}
