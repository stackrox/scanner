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

// Package rhel implements a vulnerability source updater using the
// Red Hat Linux OVAL Database.
package rhel

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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/httputil"
)

const (
	// Before this RHSA, it deals only with RHEL <= 4.
	firstRHEL5RHSA      = 20070044
	firstConsideredRHEL = 5

	ovalURI        = "https://www.redhat.com/security/data/oval/"
	allRHSAsXMLBZ2 = ovalURI + "com.redhat.rhsa-all.xml.bz2"

	bulkOVALURI = ovalURI + "v2/"
)

var (
	bulkRHSAXMLBZ2URLs = []string{
		allRHSAsXMLBZ2,
		bulkOVALURI + "RHEL6/rhel-6.oval.xml.bz2",
		bulkOVALURI + "RHEL7/rhel-7-including-unpatched.oval.xml.bz2",
		bulkOVALURI + "RHEL8/rhel-8-including-unpatched.oval.xml.bz2",
	}

	ignoredCriterions = []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}

	cveIDRegexp    = regexp.MustCompile(`^oval:com\.redhat\.cve:def:(\d+)$`)
	rhsaIDRegexp   = regexp.MustCompile(`^oval:com\.redhat\.rhsa:def:(\d+)$`)
	rhsaFileRegexp = regexp.MustCompile(`com.redhat.rhsa-(\d+).xml`)
)

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	ID          string      `xml:"id,attr"`
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	CVEs        []cve       `xml:"metadata>advisory>cve"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type cve struct {
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	ID     string `xml:",chardata"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	Comment string `xml:"comment,attr"`
}

type updater struct{}

const (
	maxRetries             = 100
	initialBackoffDuration = time.Second
	backoffMultiplier      = 2
	maxBackoffDuration     = 30 * time.Second
)

var (
	client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: proxy.RoundTripper(),
	}
)

func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Failed to update RHEL")
		return nil, fmt.Errorf("failed to update RHEL: got status code %d", resp.StatusCode)
	}

	return resp, nil
}

func getWithRetriesAndBackoff(url string) (*http.Response, error) {
	currentBackoffDuration := initialBackoffDuration
	for i := 0; i < maxRetries; i++ {
		resp, err := httpGet(url)
		if err == nil {
			return resp, nil
		}
		log.WithField("FailedAttempts", i+1).WithField("url", url).WithError(err).Info("Failed to make request to RHEL. Retrying...")
		currentBackoffDuration *= backoffMultiplier
		if currentBackoffDuration > maxBackoffDuration {
			currentBackoffDuration = maxBackoffDuration
		}
		time.Sleep(currentBackoffDuration)
	}
	return nil, fmt.Errorf("failed to make request to URL %s after retries", url)
}

func init() {
	vulnsrc.RegisterUpdater("rhel", &updater{})
}

func parseBzip(reader io.ReadCloser, coveredIDs set.IntSet) (resp []database.Vulnerability, err error) {
	defer utils.IgnoreError(reader.Close)

	decompressingReader := bzip2.NewReader(reader)
	return parseRHSA(decompressingReader, coveredIDs)
}

func (u *updater) Update(datastore vulnsrc.DataStore) (vulnsrc.UpdateResponse, error) {
	log.WithField("package", "RHEL").Info("Start fetching vulnerabilities")

	log.Info("RHEL: fetching bulk OVAL URIs")
	// RedHat has one giant file with almost all the RHSAs, except some which they don't keep in this for some reason.
	// We fetch this file first, since it's just one HTTP call.
	// We then iterate over the list of other files, and fetch all the RHSAs that weren't included in this one.

	var finalResp vulnsrc.UpdateResponse
	coveredIDs := set.NewIntSet()
	for _, url := range bulkRHSAXMLBZ2URLs {
		rhsaResp, err := getWithRetriesAndBackoff(url)
		if err != nil {
			log.WithError(err).Errorf("could not download RHEL's OVAL file from %s", url)
			return finalResp, commonerr.ErrCouldNotDownload
		}
		previouslyCovered := len(coveredIDs)
		vulns, err := parseBzip(rhsaResp.Body, coveredIDs)
		if err != nil {
			log.WithError(err).Errorf("could not prase RHEL's OVAL file from %s", url)
			return finalResp, commonerr.ErrCouldNotParse
		}
		log.Infof("RHEL: done fetching OVAL file %s. Got %d vulns (%d RHSAs)", url, len(vulns), coveredIDs.Cardinality()-previouslyCovered)

		finalResp.Vulnerabilities = append(finalResp.Vulnerabilities, vulns...)
	}

	log.Info("RHEL: Fetching remaining IDs which weren't in the OVAL files")
	ovalDirectoryResp, err := getWithRetriesAndBackoff(ovalURI)
	if err != nil {
		log.WithError(err).Error("could not fetch RHEL's update list")
		return finalResp, commonerr.ErrCouldNotDownload
	}
	defer utils.IgnoreError(ovalDirectoryResp.Body.Close)

	var remainingRHSAURLs []string
	scanner := bufio.NewScanner(ovalDirectoryResp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		regexMatch := rhsaFileRegexp.FindStringSubmatch(line)
		// Not an RHSA
		if len(regexMatch) != 2 {
			continue
		}
		rhsaNo, err := strconv.Atoi(regexMatch[1])
		if err != nil {
			return finalResp, errors.Wrapf(err, "invalid RHSA file name: %s. Bad regex?", regexMatch[0])
		}
		if rhsaNo > firstRHEL5RHSA && !coveredIDs.Contains(rhsaNo) {
			remainingRHSAURLs = append(remainingRHSAURLs, regexMatch[0])
		}
	}

	const printEvery = 100
	log.WithField("count", len(remainingRHSAURLs)).Info("RHEL: got remaining RHSAs to fetch")
	for i, rhsaURL := range remainingRHSAURLs {
		r, err := getWithRetriesAndBackoff(ovalURI + rhsaURL)
		if err != nil {
			log.WithError(err).Error("could not download RHEL's update list")
			return finalResp, commonerr.ErrCouldNotDownload
		}
		currentVulns, err := parseRHSA(r.Body, coveredIDs)
		_ = r.Body.Close()
		if err != nil {
			return finalResp, err
		}
		finalResp.Vulnerabilities = append(finalResp.Vulnerabilities, currentVulns...)
		if (i+1)%printEvery == 0 {
			log.Infof("Finished collecting %d/%d additional RHSAs", i+1, len(remainingRHSAURLs))
		}
	}
	return finalResp, nil
}

func (u *updater) Clean() {}

func parseRHSA(ovalReader io.Reader, parsedRHSAIDs set.IntSet) (vulnerabilities []database.Vulnerability, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithError(err).Error("could not decode RHEL's XML")
		err = commonerr.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		cveRegexMatch := cveIDRegexp.FindStringSubmatch(definition.ID)
		if len(cveRegexMatch) >= 2 && len(definition.References) > 0 {
			pkgs := toFeatureVersions(definition.Criteria)
			if len(pkgs) == 0 {
				continue
			}

			ref := definition.References[0]
			cveVuln := database.Vulnerability{
				Name:        ref.ID,
				Link:        ref.URI,
				Severity:    database.UnknownSeverity,
				Description: description(definition),
			}
			cveVuln.FixedIn = append(cveVuln.FixedIn, pkgs...)
			vulnerabilities = append(vulnerabilities, cveVuln)
			continue
		}

		regexMatch := rhsaIDRegexp.FindStringSubmatch(definition.ID)
		// Not an RHSA, some other kind of RHEL ID
		if len(regexMatch) < 2 {
			// Make sure we don't miss anything.
			if !(strings.HasPrefix(definition.ID, "oval:com.redhat.rhba:def") || strings.HasPrefix(definition.ID, "oval:com.redhat.rhea:def")) {
				return nil, errors.Wrapf(err, "invalid ID: %s", definition.ID)
			}
			continue
		}
		rhsaNo, err := strconv.Atoi(regexMatch[1])
		if err != nil {
			return nil, errors.Wrapf(err, "invalid RHSA id format: %s", definition.ID)
		}
		if rhsaNo < firstRHEL5RHSA {
			continue
		}
		// If we have already parsed this RHSA, then don't parse it again
		// This can happen because we parse the giant file of RHSAs and then individual files
		// for each Release (e.g. RHEL6, RHEL7, RHEL8)
		if !parsedRHSAIDs.Add(rhsaNo) {
			continue
		}
		pkgs := toFeatureVersions(definition.Criteria)
		if len(pkgs) > 0 {
			rhsaVuln := database.Vulnerability{
				Name:        name(definition),
				Link:        link(definition),
				Severity:    severity(definition),
				Description: description(definition),
			}
			rhsaVuln.FixedIn = append(rhsaVuln.FixedIn, pkgs...)
			subCVEs := make([]string, 0, len(definition.CVEs))
			for _, c := range definition.CVEs {
				subCVEs = append(subCVEs, c.ID)
			}
			rhsaVuln.SubCVEs = subCVEs

			vulnerabilities = append(vulnerabilities, rhsaVuln)

			// Add all of the CVE based vulns
			for _, c := range definition.CVEs {
				vulnerabilities = append(vulnerabilities, database.Vulnerability{
					Name:      c.ID,
					Namespace: rhsaVuln.Namespace,
					Link:      c.Href,
					FixedIn:   rhsaVuln.FixedIn,
					Severity:  database.UnknownSeverity,
				})
			}
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

	if node.Operator == "AND" {
		return [][]criterion{criterions}
	} else if node.Operator == "OR" {
		var possibilities [][]criterion
		for _, c := range criterions {
			possibilities = append(possibilities, []criterion{c})
		}
		return possibilities
	}

	return [][]criterion{}
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
	if node.Operator == "AND" {
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
	} else if node.Operator == "OR" {
		for _, possibilityGroup := range possibilitiesToCompose {
			possibilities = append(possibilities, possibilityGroup...)
		}
	}

	return possibilities
}

func toFeatureVersions(criteria criteria) []database.FeatureVersion {
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.FeatureVersion)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion database.FeatureVersion
			osVersion      int
			err            error
		)
		featureVersion.Version = versionfmt.MaxVersion

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				if strings.HasPrefix(c.Comment, "Red Hat Enterprise Linux ") {
					const prefixLen = len("Red Hat Enterprise Linux ")
					osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
					if err != nil {
						log.WithField("criterion comment", c.Comment).Warning("could not parse Red Hat release version from criterion comment")
					}
				} else {
					feature := strings.TrimSuffix(c.Comment, " is installed")
					featureVersion.Feature.Name = feature
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				version := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				err := versionfmt.Valid(rpm.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				} else {
					featureVersion.Version = version
					featureVersion.Feature.Namespace.VersionFormat = rpm.ParserName
				}
			}
		}

		if osVersion >= firstConsideredRHEL {
			// TODO(vbatts) this is where features need multiple labels ('centos' and 'rhel')
			featureVersion.Feature.Namespace.Name = "centos" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

		if featureVersion.Feature.Namespace.Name != "" && featureVersion.Feature.Name != "" {
			featureVersionParameters[featureVersion.Feature.Namespace.Name+":"+featureVersion.Feature.Name] = featureVersion
		} else {
			log.WithField("criterions", fmt.Sprintf("%v", criterions)).Warning("could not determine a valid package from criterions")
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []database.FeatureVersion
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
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
	return strings.TrimSpace(def.Title[:strings.Index(def.Title, ": ")])
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "RHSA" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) database.Severity {
	switch strings.TrimSpace(def.Title[strings.LastIndex(def.Title, "(")+1 : len(def.Title)-1]) {
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine vulnerability severity from: %s.", def.Title)
		return database.UnknownSeverity
	}
}
