// Copyright 2019 clair authors
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
// Ubuntu Linux OVAL Database.
package ubuntu

import (
	"bufio"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
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
	ovalURI = "https://people.canonical.com/~ubuntu-security/oval/"

	// "Thu, 30 Nov 2017 03:07:57 GMT
	timeFormatLastModified = "Mon, 2 Jan 2006 15:04:05 MST"

	// timestamp format 2017-10-23T04:07:14
	timeFormatOVAL = "2006-1-2T15:04:05"

	updaterFlag = "ubuntuUpdater"

	ubuntuOvalFilePrefix = "com.ubuntu."
)

var (
	ignoredCriterions          []string
	ubuntuPackageCommentRegexp = regexp.MustCompile(`^(.*) package in ([a-z]+) (?:(?:was vulnerable|is related to the CVE in some way) but has been fixed \(note: '(.*)'\)|is affected and needs fixing).$`)
	ubuntuOvalFileRegexp       = regexp.MustCompile(`com.ubuntu.([a-z]+).cve.oval.xml.bz2`)
	ubuntuOvalIgnoredRegexp    = regexp.MustCompile(`(artful|cosmic|trusty|precise)`)
)

type oval struct {
	Timestamp   string       `xml:"generator>timestamp"`
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Criteria    criteria    `xml:"criteria"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("ubuntu", &updater{})
}

func (u *updater) Update(datastore vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Ubuntu Linux").Info("Start fetching vulnerabilities")

	// ubuntu has one single xml file per release for all the products,
	// there are no incremental xml files. We store into the database
	// the value of the generation timestamp of the latest file we
	// parsed.
	flagValue, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}
	log.WithField("flagvalue", flagValue).Debug("Generation timestamp of latest parsed file")

	if flagValue == "" {
		flagValue = "0"
	}

	// this contains the modification time of the most recent
	// file expressed as unix time (int64)
	latestOval, err := strconv.ParseInt(flagValue, 10, 64)
	if err != nil {
		// something went wrong, force parsing of all files
		latestOval = 0
	}

	// Fetch the update list.
	r, err := http.Get(ovalURI)
	if err != nil {
		err = fmt.Errorf("cannot download Ubuntu update list: %v", err)
		return resp, err
	}
	defer r.Body.Close()

	var ovalFiles []string
	var generationTimes []int64

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := ubuntuOvalFileRegexp.FindStringSubmatch(line)
		if len(r) != 2 {
			continue
		}
		release := r[1]

		// check if we should ignore this release
		ignored := ubuntuOvalIgnoredRegexp.FindString(release)
		if ignored != "" {
			continue
		}

		ovalFile := ovalURI + ubuntuOvalFilePrefix + release + ".cve.oval.xml.bz2"
		log.WithFields(log.Fields{
			"ovalFile": ovalFile,
			"updater":  "Ubuntu Linux",
		}).Debug("file to check")

		// Do not fetch the entire file to get the value of the
		// creation time. Rely on the "latest modified time"
		// value of the file hosted on the remote server.
		timestamp, err := getLatestModifiedTime(ovalFile)
		if err != nil {
			log.WithError(err).WithField("ovalFile", ovalFile).Warning("Ignoring OVAL file")
		}

		if timestamp > latestOval {
			ovalFiles = append(ovalFiles, ovalFile)
		}
	}

	for _, oval := range ovalFiles {
		log.WithFields(log.Fields{
			"ovalFile": oval,
			"updater":  "Ubuntu Linux",
		}).Debug("downloading")
		// Download the oval XML file.
		r, err := http.Get(oval)
		if err != nil {
			log.WithError(err).Error("could not download Ubuntu update list")
			return resp, commonerr.ErrCouldNotDownload
		}

		// Parse the XML.
		vs, generationTime, err := parseOval(bzip2.NewReader(r.Body))
		if err != nil {
			return resp, err
		}
		generationTimes = append(generationTimes, generationTime)

		// Collect vulnerabilities.
		resp.Vulnerabilities = append(resp.Vulnerabilities, vs...)
	}

	// Set the flag if we found anything.
	if len(generationTimes) > 0 {
		resp.FlagName = updaterFlag
		resp.FlagValue = strconv.FormatInt(latest(generationTimes), 10)
	} else {
		log.WithField("package", "Ubuntu Linux").Debug("no update")
	}

	return resp, nil
}

// Get the latest modification time of a remote file
// expressed as unix time
func getLatestModifiedTime(url string) (int64, error) {
	resp, err := http.Head(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	lastModified := resp.Header.Get("Last-Modified")
	if len(lastModified) == 0 {
		return 0, fmt.Errorf("last modified header missing")
	}

	timestamp, err := time.Parse(timeFormatLastModified, lastModified)
	if err != nil {
		return 0, err
	}

	return timestamp.Unix(), nil
}

func latest(values []int64) (ret int64) {
	for _, element := range values {
		if element > ret {
			ret = element
		}
	}
	return
}

func (u *updater) Clean() {}

func parseOval(ovalReader io.Reader) (vulnerabilities []database.Vulnerability, generationTime int64, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithError(err).Error("could not decode XML")
		err = commonerr.ErrCouldNotParse
		return
	}

	timestamp, err := time.Parse(timeFormatOVAL, ov.Timestamp)
	if err != nil {
		return
	}
	generationTime = timestamp.Unix()

	// Iterate over the definitions and collect any vulnerabilities
	// that affect at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatureVersions(definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := database.Vulnerability{
				Name:        name(definition),
				Link:        link(definition),
				Severity:    severity(definition),
				Description: description(definition),
				FixedIn:     pkgs,
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return
}

func getCriterions(node criteria) [][]criterion {
	// Filter useless criterions.
	var criterions []criterion
	for _, c := range node.Criterions {
		ignored := false

		for _, ignoredItem := range ignoredCriterions {
			if strings.Contains(c.Comment, ignoredItem) {
				ignored = true
				break
			}
		}

		if !ignored {
			criterions = append(criterions, c)
		}
	}

	// assume AND if not specifically OR
	if node.Operator == "OR" {
		var possibilities [][]criterion
		for _, c := range criterions {
			possibilities = append(possibilities, []criterion{c})
		}
		return possibilities
	}
	return [][]criterion{criterions}
}

func getPossibilities(node criteria) [][]criterion {
	if len(node.Criterias) == 0 {
		return getCriterions(node)
	}

	var possibilitiesToCompose [][][]criterion
	for _, criteria := range node.Criterias {
		possibilitiesToCompose = append(possibilitiesToCompose, getPossibilities(*criteria))
	}
	if len(node.Criterions) > 0 {
		possibilitiesToCompose = append(possibilitiesToCompose, getCriterions(node))
	}

	var possibilities [][]criterion
	// assume AND if not OR
	if node.Operator == "OR" {
		for _, possibilityGroup := range possibilitiesToCompose {
			possibilities = append(possibilities, possibilityGroup...)
		}
	} else {
		possibilities = append(possibilities, possibilitiesToCompose[0]...)

		for _, possibilityGroup := range possibilitiesToCompose[1:] {
			var newPossibilities [][]criterion

			for _, possibility := range possibilities {
				for _, possibilityInGroup := range possibilityGroup {
					var p []criterion
					p = append(p, possibility...)
					p = append(p, possibilityInGroup...)
					newPossibilities = append(newPossibilities, p)
				}
			}

			possibilities = newPossibilities
		}
	}

	return possibilities
}

func toFeatureVersions(criteria criteria) []database.FeatureVersion {
	var featureVersionParametersArray []database.FeatureVersion
	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var featureVersion database.FeatureVersion

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if match := ubuntuPackageCommentRegexp.FindStringSubmatch(c.Comment); match != nil {
				var version = versionfmt.MaxVersion
				if len(match[3]) > 0 {
					version = match[3]
					err := versionfmt.Valid(dpkg.ParserName, version)
					if err != nil {
						log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
					}
				}
				featureVersion.Version = version
				featureVersion.Feature = database.Feature{
					Name: match[1],
					Namespace: database.Namespace{
						Name:          fmt.Sprintf("ubuntu:%s", match[2]),
						VersionFormat: dpkg.ParserName,
					},
				}
			}
		}

		if featureVersion.Feature.Namespace.Name != "" && featureVersion.Feature.Name != "" {
			featureVersionParametersArray = append(featureVersionParametersArray, featureVersion)
		}
	}

	return featureVersionParametersArray
}

func description(def definition) (desc string) {
	// It is much more faster to proceed like this than using a Replacer.
	desc = strings.Replace(def.Description, "\n\n\n", " ", -1)
	desc = strings.Replace(desc, "\n\n", " ", -1)
	desc = strings.Replace(desc, "\n", " ", -1)
	return
}

func name(def definition) string {
	// only return the CVE identifier which is the first word
	return strings.Split(def.Title, " ")[0]
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "CVE" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) (severity database.Severity) {
	switch def.Severity {
	case "":
		return database.UnknownSeverity
	case "Untriaged":
		return database.UnknownSeverity
	case "Negligible":
		return database.NegligibleSeverity
	case "Low":
		return database.LowSeverity
	case "Medium":
		return database.MediumSeverity
	case "High":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine a vulnerability severity from: %s", def.Severity)
		return database.UnknownSeverity

	}
}
