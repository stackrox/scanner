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

// Package ubuntu implements a vulnerability source updater using the
// Ubuntu CVE Tracker.
package ubuntu

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
)

const (
	trackerGitURL = "git://git.launchpad.net/ubuntu-cve-tracker"
	updaterFlag   = "ubuntuUpdater"

	// LegacyCVEURLPrefix is the legacy CVE URL prefix used.
	LegacyCVEURLPrefix = "http://people.ubuntu.com/~ubuntu-security/cve/"
	// CVEURLPrefix is the current CVE URL prefix to use.
	CVEURLPrefix = "https://ubuntu.com/security/"

	xenialESMLinePrefix = "esm-infra/xenial_"
)

var (
	ubuntuIgnoredReleases = map[string]struct{}{
		"upstream": {},
		"devel":    {},

		"dapper":   {},
		"edgy":     {},
		"feisty":   {},
		"gutsy":    {},
		"hardy":    {},
		"intrepid": {},
		"jaunty":   {},
		"karmic":   {},
		"lucid":    {},
		"maverick": {},
		"natty":    {},
		"oneiric":  {},
		"saucy":    {},

		"vivid/ubuntu-core":          {},
		"vivid/stable-phone-overlay": {},

		// Syntax error
		"Patches": {},
		// Product
		"product": {},
	}

	affectsCaptureRegexp      = regexp.MustCompile(`(esm-infra/)?(?P<release>.*)_(?P<package>.*): (?P<status>[^\s]*)( \(+(?P<note>[^()]*)\)+)?`)
	affectsCaptureRegexpNames = affectsCaptureRegexp.SubexpNames()
)

type updater struct {
	repositoryLocalPath string
}

func init() {
	vulnsrc.RegisterUpdater("ubuntu", &updater{})
}

func (u *updater) Update(datastore vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Ubuntu").Info("Start fetching vulnerabilities")

	// Pull the master branch.
	var commit string
	commit, err = u.pullRepositoryWithRetries()
	if err != nil {
		return
	}

	log.WithField("updater", "ubuntu").Info("git repository pulled successfully")

	// Get the latest revision number we successfully applied in the database.
	dbCommit, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	// Short-circuit if there have been no updates.
	if commit == dbCommit {
		log.WithField("package", "ubuntu").Debug("no update")
		return
	}

	log.WithField("updater", "ubuntu").Info("Collecting modified vulnerabilities")
	// Get the list of vulnerabilities that we have to update.
	modifiedCVE, err := collectModifiedVulnerabilities(u.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	log.WithField("updater", "ubuntu").Infof("Got %d CVEs to parse", len(modifiedCVE))

	notes := make(map[string]struct{})
	for cvePath := range modifiedCVE {
		// Open the CVE file.
		file, err := os.Open(u.repositoryLocalPath + "/" + cvePath)
		if err != nil {
			// This can happen when a file is modified and then moved in another
			// commit.
			continue
		}

		// Parse the vulnerability.
		v, unknownReleases, err := parseUbuntuCVE(file)
		if err != nil {
			return resp, err
		}

		// Add the vulnerability to the response.
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)

		// Store any unknown releases as notes.
		for k := range unknownReleases {
			note := fmt.Sprintf("Ubuntu %s is not mapped to any version number (eg. trusty->14.04). Please update me.", k)
			notes[note] = struct{}{}

			// If we encountered unknown Ubuntu release, we don't want the revision
			// number to be considered as managed.
			commit = dbCommit
		}

		// Close the file manually.
		//
		// We do that instead of using defer because defer works on a function-level scope.
		// We would open many files and close them all at once at the end of the function,
		// which could lead to exceed fs.file-max.
		file.Close()
	}

	// Add flag and notes.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit
	for note := range notes {
		resp.Notes = append(resp.Notes, note)
	}

	return
}

func (u *updater) Clean() {
	os.RemoveAll(u.repositoryLocalPath)
}

const (
	maxRetries          = 5
	sleepBetweenRetries = time.Minute
)

func (u *updater) pullRepositoryWithRetries() (string, error) {
	for try := 1; ; try++ {
		// This ensures we clone from scratch into a new temp directory.
		u.repositoryLocalPath = ""

		commit, err := u.pullRepository()
		if err == nil {
			return commit, nil
		}
		if u.repositoryLocalPath != "" {
			if err := os.RemoveAll(u.repositoryLocalPath); err != nil {
				log.WithError(err).Warnf("Ubuntu: Failed to remove local git repo path: %q", u.repositoryLocalPath)
			}
		}
		if try >= maxRetries {
			return "", err
		}
		log.WithError(err).WithField("try", try).Warn("Failed to pull ubuntu updater, will retry...")
		time.Sleep(sleepBetweenRetries)
	}
}

func (u *updater) pullRepository() (commit string, err error) {
	// If the repository doesn't exist, clone it.
	if _, pathExists := os.Stat(u.repositoryLocalPath); u.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		if u.repositoryLocalPath, err = os.MkdirTemp("", "ubuntu-cve-tracker"); err != nil {
			return "", vulnsrc.ErrFilesystem
		}

		log.WithField("updater", "ubuntu").Infof("running git clone to %s", u.repositoryLocalPath)
		cmd := exec.Command("git", "clone", "--depth", "1", trackerGitURL, ".")
		cmd.Dir = u.repositoryLocalPath
		if out, err := cmd.CombinedOutput(); err != nil {
			u.Clean()
			log.WithError(err).WithField("output", string(out)).Error("could not pull ubuntu-cve-tracker repository")
			return "", commonerr.ErrCouldNotDownload
		}
	} else {
		// The repository already exists and it needs to be refreshed via a pull.
		cmd := exec.Command("git", "pull")
		cmd.Dir = u.repositoryLocalPath
		if _, err := cmd.CombinedOutput(); err != nil {
			return "", vulnsrc.ErrGitFailure
		}
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = u.repositoryLocalPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", vulnsrc.ErrGitFailure
	}

	commit = strings.TrimSpace(string(out))
	return
}

func collectModifiedVulnerabilities(repositoryLocalPath string) (map[string]struct{}, error) {
	modifiedCVE := make(map[string]struct{})

	// Handle a brand new database.

	for _, folder := range []string{"active", "retired"} {
		d, err := os.Open(repositoryLocalPath + "/" + folder)
		if err != nil {
			log.WithError(err).Error("could not open Ubuntu vulnerabilities repository's folder")
			return nil, vulnsrc.ErrFilesystem
		}

		// Get the FileInfo of all the files in the directory.
		names, err := d.Readdirnames(-1)
		if err != nil {
			log.WithError(err).Error("could not read Ubuntu vulnerabilities repository's folder")
			return nil, vulnsrc.ErrFilesystem
		}

		// Add the vulnerabilities to the list.
		for _, name := range names {
			if strings.HasPrefix(name, "CVE-") {
				modifiedCVE[folder+"/"+name] = struct{}{}
			}
		}

		// Close the file manually.
		//
		// We do that instead of using defer because defer works on a function-level scope.
		// We would open many files and close them all at once at the end of the function,
		// which could lead to exceed fs.file-max.
		d.Close()
	}

	return modifiedCVE, nil
}

func parseUbuntuCVE(fileContent io.Reader) (vulnerability database.Vulnerability, unknownReleases map[string]struct{}, err error) {
	unknownReleases = make(map[string]struct{})
	readingDescription := false
	scanner := bufio.NewScanner(fileContent)

	type fvKey struct {
		namespace, name, version string
	}
	addFVs := make(map[fvKey]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip any comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the name.
		if strings.HasPrefix(line, "Candidate:") {
			vulnerability.Name = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			vulnerability.Link = CVEURLPrefix + vulnerability.Name
			continue
		}

		// Parse the priority.
		if strings.HasPrefix(line, "Priority:") {
			priority := strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))

			// Handle syntax error: Priority: medium (heap-protector)
			if strings.Contains(priority, " ") {
				//nolint:gocritic
				priority = priority[:strings.Index(priority, " ")]
			}

			vulnerability.Severity = SeverityFromPriority(priority)
			continue
		}

		// Parse the description.
		if strings.HasPrefix(line, "Description:") {
			readingDescription = true
			vulnerability.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:")) // In case there is a formatting error and the description starts on the same line
			continue
		}
		if readingDescription {
			if strings.HasPrefix(line, "Ubuntu-Description:") || strings.HasPrefix(line, "Notes:") || strings.HasPrefix(line, "Bugs:") || strings.HasPrefix(line, "Priority:") || strings.HasPrefix(line, "Discovered-by:") || strings.HasPrefix(line, "Assigned-to:") {
				readingDescription = false
			} else {
				vulnerability.Description = vulnerability.Description + " " + line
				continue
			}
		}

		// Try to parse the package that the vulnerability affects.
		affectsCaptureArr := affectsCaptureRegexp.FindAllStringSubmatch(line, -1)
		if len(affectsCaptureArr) > 0 {
			affectsCapture := affectsCaptureArr[0]

			md := map[string]string{}
			for i, n := range affectsCapture {
				md[affectsCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			// Only consider the package if its status is needed, active, deferred, not-affected or
			// released. Ignore DNE (package does not exist), needs-triage, ignored, pending.
			if md["status"] == "needed" || md["status"] == "active" || md["status"] == "deferred" || md["status"] == "released" || md["status"] == "not-affected" {
				md["release"] = strings.Split(md["release"], "/")[0]
				if _, isReleaseIgnored := ubuntuIgnoredReleases[md["release"]]; isReleaseIgnored {
					continue
				}
				if _, isReleaseKnown := database.UbuntuReleasesMapping[md["release"]]; !isReleaseKnown {
					unknownReleases[md["release"]] = struct{}{}
					continue
				}

				var version string
				switch {
				case md["status"] == "released":
					if md["note"] != "" {
						err := versionfmt.Valid(dpkg.ParserName, md["note"])
						if err != nil {
							log.WithError(err).WithFields(log.Fields{
								"package":      "ubuntu",
								"version":      md["note"],
								"package name": md["package"],
							}).Warning("could not parse package version, skipping")
						}
						version = md["note"]
					}
				case md["status"] == "not-affected":
					version = versionfmt.MinVersion
				default:
					version = versionfmt.MaxVersion
				}
				if version == "" {
					continue
				}

				namespace := "ubuntu:" + database.UbuntuReleasesMapping[md["release"]]
				fvKey := fvKey{
					namespace: namespace,
					name:      md["package"],
					version:   version,
				}

				// For now, only dedupe feature versions when the prefix is the Xenial ESM
				// because otherwise there will be a large number of diffs in the dump
				if strings.HasPrefix(line, xenialESMLinePrefix) {
					if _, ok := addFVs[fvKey]; ok {
						continue
					}
				}

				// Create and add the new package.
				featureVersion := database.FeatureVersion{
					Feature: database.Feature{
						Namespace: database.Namespace{
							Name:          namespace,
							VersionFormat: dpkg.ParserName,
						},
						Name: md["package"],
					},
					Version: version,
				}
				addFVs[fvKey] = struct{}{}
				vulnerability.FixedIn = append(vulnerability.FixedIn, featureVersion)
			}
		}
	}

	// Trim extra spaces in the description
	vulnerability.Description = strings.TrimSpace(vulnerability.Description)

	// If no link has been provided (CVE-2006-NNN0 for instance), add the link to the tracker
	if vulnerability.Link == "" {
		vulnerability.Link = trackerGitURL
	}

	// If no priority has been provided (CVE-2007-0667 for instance), set the priority to Unknown
	if vulnerability.Severity == "" {
		vulnerability.Severity = database.UnknownSeverity
	}

	return
}

// SeverityFromPriority converts an priority from the Ubuntu CVE Tracker into
// a database.Severity.
func SeverityFromPriority(priority string) database.Severity {
	switch priority {
	case "untriaged":
		return database.UnknownSeverity
	case "negligible":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "medium":
		return database.MediumSeverity
	case "high":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine a vulnerability severity from: %s", priority)
		return database.UnknownSeverity
	}
}
