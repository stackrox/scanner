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
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/metrics"
	"github.com/stackrox/scanner/pkg/rhelv2/rpm"
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

func (l lister) ListFeatures(files analyzer.Files) ([]database.FeatureVersion, error) {
	f, hasFile := files.Get(dbPath)
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	pkgFmt := `rpm`
	defer metrics.ObserveListFeaturesTime(pkgFmt, "all", time.Now())

	// Write the required "Packages" file to disk
	tmpDir, err := os.MkdirTemp("", "rpm")
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for RPM detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	err = os.WriteFile(tmpDir+"/Packages", f.Contents, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for RPM detection")
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	// Extract binary package names because RHSA refers to binary package names.
	defer metrics.ObserveListFeaturesTime(pkgFmt, "cli+parse", time.Now())
	cmd := exec.Command("rpm", "--dbpath", tmpDir, "-qa", "--qf", queryFmt)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return []database.FeatureVersion{}, errors.Wrap(err, "Unable to get pipe for RPM command")
	}
	defer utils.IgnoreError(r.Close)

	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf

	if err := cmd.Start(); err != nil {
		return []database.FeatureVersion{}, errors.Wrap(err, "Could not start RPM query: either the DB is corrupted or FIPs mode is enabled")
	}

	featureVersions, err := parseFeatures(r, files)
	if err != nil {
		if errbuf.Len() != 0 {
			log.Warnf("Error executing RPM command: %s", errbuf.String())
		}
		return nil, errors.Wrap(err, "Could not query RPM: either the DB is corrupted or FIPs mode is enabled")
	}

	if err := cmd.Wait(); err != nil {
		return nil, errors.Wrap(err, "Could not wait for RPM query: either the DB is corrupted or FIPs mode is enabled")
	}

	return featureVersions, nil
}

func parseFeatures(r io.Reader, files analyzer.Files) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	var fv database.FeatureVersion
	// execToDeps and libToDeps ensures only unique executables or libraries are stored per package.
	execToDeps := make(database.StringToStringsMap)
	libToDeps := make(database.StringToStringsMap)
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
			if fv.Feature.Name != "" && fv.Version != "" {
				if len(execToDeps) > 0 {
					fv.ExecutableToDependencies = execToDeps
				}
				if len(libToDeps) > 0 {
					fv.LibraryToDependencies = libToDeps
				}
				featureVersions = append(featureVersions, fv)
			}

			// Start a new package definition and reset 'i'.
			fv = database.FeatureVersion{}
			execToDeps = make(database.StringToStringsMap)
			libToDeps = make(database.StringToStringsMap)
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
			// The first character is always "/", which is removed when inserted into the layer files.
			fileData, hasFile := files.Get(filename[1:])
			if hasFile {
				rpm.AddToDependencyMap(filename, fileData, execToDeps, libToDeps)
			}
		}
	}

	return featureVersions, s.Err()
}

func (l lister) RequiredFilenames() []string {
	return []string{dbPath}
}
