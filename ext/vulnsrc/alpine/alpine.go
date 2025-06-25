// Copyright 2018 clair authors
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

// Package alpine implements a vulnerability source updater using the
// alpine-secdb git repository.
package alpine

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/fsutil"
	"sigs.k8s.io/yaml"
)

const (
	baseURL     = "https://secdb.alpinelinux.org/" // Web source for alpine vuln data
	updaterFlag = "alpine-secdbUpdater"
	// LegacyMitreURLPrefix is for legacy CVE link
	LegacyMitreURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	// MitreURLPrefix is the most updated CVE Link
	MitreURLPrefix = "https://www.cve.org/CVERecord?id="
)

func init() {
	vulnsrc.RegisterUpdater("alpine", &updater{})
}

type updater struct {
	repositoryLocalPath string
	currentDir          string
}

func (u *updater) processFile(filename string) {
	nameParts := strings.Split(filename, ".")
	if nameParts[1] == "json" {
		return
	}

	response, err := http.Get(baseURL + u.currentDir + filename)
	if err != nil {
		return
	}
	defer response.Body.Close()

	file, err := os.Create(filepath.Join(filepath.Join(u.repositoryLocalPath, u.currentDir), filename))
	if err != nil {
		log.WithField("package", "Alpine").Fatal(err)
		return
	}
	defer file.Close()

	fileContents, err := io.ReadAll(response.Body)
	if err != nil {
		log.WithField("package", "Alpine").Fatal(err)
		return
	}

	file.WriteString(string(fileContents))
}

func (u *updater) processFiles(_ int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		if href != "../" {
			u.processFile(href)
		}
	}
}

func (u *updater) processVersionDir(versionDir string) {
	response, err := http.Get(baseURL + versionDir)
	if err != nil {
		log.WithError(err).WithField("package", "Alpine").Error("Failed to get version")
	}
	defer response.Body.Close()

	document, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		//nolint:gocritic
		log.Fatal("Error loading HTTP response body. ", err)
	}
	document.Find("a").Each(u.processFiles)
}

func (u *updater) processVersions(_ int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		if href != "../" {
			log.WithField("package", "alpine").Debug(href)
			// create Version directory
			_ = os.Mkdir(filepath.Join(u.repositoryLocalPath, href), 0700)
			u.currentDir = href
			u.processVersionDir(href)
		}
	}
}

func (u *updater) getVulnFiles(repoPath, tempDirPrefix string) (commit string, err error) {
	log.WithField("package", "alpine").Debug("Getting vulnerability data...")

	// Set up temporary location for downloads
	if repoPath == "" {
		u.repositoryLocalPath, err = os.MkdirTemp("", tempDirPrefix)
		if err != nil {
			return
		}
	} else {
		u.repositoryLocalPath = repoPath
	}

	u.currentDir = ""

	// Get root directory of web server
	response, err := http.Get(baseURL)
	if err != nil {
		return
	}
	defer response.Body.Close()

	document, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.WithError(err).WithField("package", "Alpine").Fatal("Error loading HTTP response body. ")
		return
	}
	document.Find("a").Each(u.processVersions)

	commit = "00000000000000000000000000000000"

	return
}

func (u *updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Alpine").Info("Start fetching vulnerabilities")

	// Pull the master branch.
	var commit string
	if commit, err = u.getVulnFiles(u.repositoryLocalPath, updaterFlag); err != nil {
		log.WithField("package", "alpine").Debug("no file updates, skip")
		return
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit

	// Get the list of namespaces from the repository.
	var namespaces []string
	if namespaces, err = fsutil.Readdir(u.repositoryLocalPath, fsutil.DirectoriesOnly); err != nil {
		return
	}

	// Append any changed vulnerabilities to the response.
	for _, namespace := range namespaces {
		var vulns []database.Vulnerability
		vulns, err = parseVulnsFromNamespace(u.repositoryLocalPath, namespace)
		if err != nil {
			return
		}
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
	}

	return
}

func (u *updater) Clean() {
	if u.repositoryLocalPath != "" {
		os.RemoveAll(u.repositoryLocalPath)
	}
}

func parseVulnsFromNamespace(repositoryPath, namespace string) (vulns []database.Vulnerability, err error) {
	nsDir := filepath.Join(repositoryPath, namespace)
	var dbFilenames []string
	if dbFilenames, err = fsutil.Readdir(nsDir, fsutil.FilesOnly); err != nil {
		return
	}

	for _, filename := range dbFilenames {
		var db *secDB
		if db, err = newSecDB(filepath.Join(nsDir, filename)); err != nil {
			return
		}

		vulns = append(vulns, db.Vulnerabilities()...)
	}

	return
}

type secDB struct {
	Distro   string `yaml:"distroversion"`
	Packages []struct {
		Pkg struct {
			Name  string              `yaml:"name"`
			Fixes map[string][]string `yaml:"secfixes"`
		} `yaml:"pkg"`
	} `yaml:"packages"`
}

func newSecDB(filePath string) (file *secDB, err error) {
	var f io.ReadCloser
	f, err = os.Open(filePath)
	if err != nil {
		return
	}

	defer f.Close()
	file = &secDB{}
	err = yaml.NewDecoder(f).Decode(file)
	return
}

func (file *secDB) Vulnerabilities() (vulns []database.Vulnerability) {
	if file == nil {
		return
	}

	namespace := database.Namespace{Name: "alpine:" + file.Distro, VersionFormat: apk.ParserName}
	for _, pkg := range file.Packages {
		for version, cveNames := range pkg.Pkg.Fixes {
			if err := versionfmt.Valid(apk.ParserName, version); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"package":      namespace.Name,
					"version":      version,
					"package name": pkg.Pkg.Name,
				}).Warning("could not parse package version, skipping")
				continue
			}

			for _, cve := range cveNames {
				vuln := database.Vulnerability{
					Name:      cve,
					Link:      MitreURLPrefix + cve,
					Severity:  database.UnknownSeverity,
					Namespace: namespace,
				}

				var fixedInVersion string
				if version != versionfmt.MaxVersion {
					fixedInVersion = version
				}

				vuln.FixedIn = []database.FeatureVersion{
					{
						Feature: database.Feature{
							Namespace: namespace,
							Name:      pkg.Pkg.Name,
						},
						Version: fixedInVersion,
					},
				}

				vulns = append(vulns, vuln)
			}
		}
	}

	return
}
