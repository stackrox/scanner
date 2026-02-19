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

// Package amzn implements a vulnerability source updater using
// ALAS (Amazon Linux Security Advisories).
package amzn

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/httputil"
	"github.com/stackrox/scanner/pkg/nvd"
)

const (
	amazonLinux1UpdaterFlag   = "amazonLinux1Updater"
	amazonLinux1MirrorListURI = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux1Name          = "Amazon Linux 2018.03"
	amazonLinux1Namespace     = "amzn:2018.03"
	amazonLinux1LinkFormat    = "https://alas.aws.amazon.com/%s.html"

	amazonLinux2UpdaterFlag   = "amazonLinux2Updater"
	amazonLinux2MirrorListURI = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	amazonLinux2Name          = "Amazon Linux 2"
	amazonLinux2Namespace     = "amzn:2"
	amazonLinux2LinkFormat    = "https://alas.aws.amazon.com/AL2/%s.html"
	defaultUpdaterFlagValue   = ""
)

type updater struct {
	UpdaterFlag   string
	MirrorListURI string
	Name          string
	Namespace     string
	LinkFormat    string
}

func init() {
	// Register updater for Amazon Linux 2018.03.
	amazonLinux1Updater := updater{
		UpdaterFlag:   amazonLinux1UpdaterFlag,
		MirrorListURI: amazonLinux1MirrorListURI,
		Name:          amazonLinux1Name,
		Namespace:     amazonLinux1Namespace,
		LinkFormat:    amazonLinux1LinkFormat,
	}
	vulnsrc.RegisterUpdater("amzn1", &amazonLinux1Updater)

	// Register updater for Amazon Linux 2.
	amazonLinux2Updater := updater{
		UpdaterFlag:   amazonLinux2UpdaterFlag,
		MirrorListURI: amazonLinux2MirrorListURI,
		Name:          amazonLinux2Name,
		Namespace:     amazonLinux2Namespace,
		LinkFormat:    amazonLinux2LinkFormat,
	}
	vulnsrc.RegisterUpdater("amzn2", &amazonLinux2Updater)
}

func (u *updater) Update(datastore vulnsrc.DataStore) (vulnsrc.UpdateResponse, error) {
	log.WithField("package", u.Name).Info("Start fetching vulnerabilities")

	// Get the most recent updated date of the previous update.
	flagValue, err := datastore.GetKeyValue(u.UpdaterFlag)
	if err != nil {
		return vulnsrc.UpdateResponse{}, err
	}

	// GetKeyValue returns "" if the key is not found. Coincidentally, the default flag
	// value I want to use is also the empty string. This code makes the logic explicit.
	if flagValue == "" {
		flagValue = defaultUpdaterFlagValue
	}

	var timestamp string

	// Get the ALASs from updateinfo.xml.gz from the repos.
	updateInfo, err := u.getUpdateInfo()
	if err != nil {
		return vulnsrc.UpdateResponse{}, err
	}

	// Get the ALASs which were issued/updated since the previous update.
	var alasList []ALAS
	for _, alas := range updateInfo.ALASList {
		if compareTimestamp(alas.Updated.Date, flagValue) > 0 {
			alasList = append(alasList, alas)

			if compareTimestamp(alas.Updated.Date, timestamp) > 0 {
				timestamp = alas.Updated.Date
			}
		}
	}

	// Get the vulnerabilities.
	vulnerabilities := u.alasListToVulnerabilities(alasList)

	response := vulnsrc.UpdateResponse{
		Vulnerabilities: vulnerabilities,
	}

	// Set the flag value.
	if timestamp != "" {
		response.FlagName = u.UpdaterFlag
		response.FlagValue = timestamp
	} else {
		log.WithField("package", u.Name).Debug("no update")
	}

	return response, nil
}

func (u *updater) Clean() {}

func (u *updater) getUpdateInfo() (UpdateInfo, error) {
	// Get the URI of updateinfo.xml.gz.
	updateInfoURI, err := u.getUpdateInfoURI()
	if err != nil {
		return UpdateInfo{}, err
	}

	// Download updateinfo.xml.gz.
	updateInfoResponse, err := httputil.GetWithUserAgent(updateInfoURI)
	if err != nil {
		log.WithError(err).Error("could not download updateinfo.xml.gz")
		return UpdateInfo{}, commonerr.ErrCouldNotDownload
	}
	defer updateInfoResponse.Body.Close()

	if !httputil.Status2xx(updateInfoResponse) {
		log.WithField("StatusCode", updateInfoResponse.StatusCode).Error("could not download updateinfo.xml.gz")
		return UpdateInfo{}, commonerr.ErrCouldNotDownload
	}

	// Decompress updateinfo.xml.gz.
	updateInfoXML, err := gzip.NewReader(updateInfoResponse.Body)
	if err != nil {
		log.WithError(err).Error("could not decompress updateinfo.xml.gz")
		return UpdateInfo{}, commonerr.ErrCouldNotParse
	}
	defer updateInfoXML.Close()

	// Decode updateinfo.xml.
	updateInfo, err := decodeUpdateInfo(updateInfoXML)
	if err != nil {
		log.WithError(err).Error("could not decode updateinfo.xml")
		return UpdateInfo{}, commonerr.ErrCouldNotParse
	}

	return updateInfo, nil
}

func (u *updater) getUpdateInfoURI() (string, error) {
	// Download mirror.list
	mirrorListResponse, err := httputil.GetWithUserAgent(u.MirrorListURI)
	if err != nil {
		log.WithError(err).Error("could not download mirror list")
		return "", commonerr.ErrCouldNotDownload
	}
	defer mirrorListResponse.Body.Close()

	if !httputil.Status2xx(mirrorListResponse) {
		log.WithField("StatusCode", mirrorListResponse.StatusCode).Error("could not download mirror list")
		return "", commonerr.ErrCouldNotDownload
	}

	// Parse the URI of the first mirror.
	scanner := bufio.NewScanner(mirrorListResponse.Body)
	success := scanner.Scan()
	if !success {
		log.WithError(err).Error("could not parse mirror list")
	}
	mirrorURL, err := url.Parse(scanner.Text())
	if err != nil {
		log.WithError(err).Error("invalid url returned from mirror list")
		return "", commonerr.ErrCouldNotDownload
	}

	// Download repomd.xml.
	repoMdURI := mirrorURL.JoinPath("repodata", "repomd.xml").String()
	repoMdResponse, err := httputil.GetWithUserAgent(repoMdURI)
	if err != nil {
		log.WithError(err).Error("could not download repomd.xml")
		return "", commonerr.ErrCouldNotDownload
	}
	defer repoMdResponse.Body.Close()

	if !httputil.Status2xx(repoMdResponse) {
		log.WithField("StatusCode", repoMdResponse.StatusCode).Error("could not download repomd.xml")
		return "", commonerr.ErrCouldNotDownload
	}

	// Decode repomd.xml.
	var repoMd RepoMd
	err = xml.NewDecoder(repoMdResponse.Body).Decode(&repoMd)
	if err != nil {
		log.WithError(err).Error("could not decode repomd.xml")
		return "", commonerr.ErrCouldNotDownload
	}

	// Parse the URI of updateinfo.xml.gz.
	var updateInfoURI string
	for _, repo := range repoMd.RepoList {
		if repo.Type == "updateinfo" {
			updateInfoURI = mirrorURL.JoinPath(repo.Location.Href).String()
			break
		}
	}
	if updateInfoURI == "" {
		log.Error("could not find updateinfo in repomd.xml")
		return "", commonerr.ErrCouldNotDownload
	}

	return updateInfoURI, nil
}

func decodeUpdateInfo(updateInfoReader io.Reader) (UpdateInfo, error) {
	var updateInfo UpdateInfo
	err := xml.NewDecoder(updateInfoReader).Decode(&updateInfo)
	if err != nil {
		return updateInfo, err
	}

	return updateInfo, nil
}

func (u *updater) alasListToVulnerabilities(alasList []ALAS) []database.Vulnerability {
	vulnMap := make(map[string]*database.Vulnerability)
	for _, alas := range alasList {
		subCVEs := set.NewStringSet()
		for _, ref := range alas.References {
			if strings.HasPrefix(ref.ID, "CVE-") {
				subCVEs.Add(ref.ID)
			}
		}
		featureVersions := u.alasToFeatureVersions(alas)
		if len(featureVersions) > 0 {
			name := u.alasToName(alas)
			vulnMap[name] = &database.Vulnerability{
				Name:        name,
				Link:        u.alasToLink(alas),
				Severity:    u.alasToSeverity(alas),
				Description: u.alasToDescription(alas),
				FixedIn:     featureVersions,
				SubCVEs:     subCVEs.AsSlice(),
			}
			for c := range subCVEs {
				if vuln, ok := vulnMap[c]; ok {
					vuln.FixedIn = append(vuln.FixedIn, featureVersions...)
				} else {
					vulnMap[c] = &database.Vulnerability{
						Name:        c,
						Link:        nvd.Link(c),
						Severity:    database.UnknownSeverity,
						Description: u.alasToDescription(alas),
						FixedIn:     featureVersions,
					}
				}
			}
		}
	}
	vulnerabilities := make([]database.Vulnerability, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		vulnerabilities = append(vulnerabilities, *vuln)
	}
	return vulnerabilities
}

func (u *updater) alasToName(alas ALAS) string {
	return alas.ID
}

func (u *updater) alasToLink(alas ALAS) string {
	if u.Name == amazonLinux1Name {
		return fmt.Sprintf(u.LinkFormat, alas.ID)
	}

	if u.Name == amazonLinux2Name {
		// "ALAS2-2018-1097" becomes "https://alas.aws.amazon.com/AL2/ALAS-2018-1097.html".
		re := regexp.MustCompile(`^ALAS2-(.+)$`)
		return fmt.Sprintf(u.LinkFormat, "ALAS-"+re.FindStringSubmatch(alas.ID)[1])
	}

	return ""
}

func (u *updater) alasToSeverity(alas ALAS) database.Severity {
	switch alas.Severity {
	case "low":
		return database.LowSeverity
	case "medium":
		return database.MediumSeverity
	case "important":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", alas.Severity).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}

func (u *updater) alasToDescription(alas ALAS) string {
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(strings.TrimSpace(alas.Description), " ")
}

func (u *updater) alasToFeatureVersions(alas ALAS) []database.FeatureVersion {
	var featureVersions []database.FeatureVersion
	for _, p := range alas.Packages {
		var version string
		if p.Epoch == "0" {
			version = p.Version + "-" + p.Release
		} else {
			version = p.Epoch + ":" + p.Version + "-" + p.Release
		}
		err := versionfmt.Valid(rpm.ParserName, version)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package":      u.Namespace,
				"version":      version,
				"package name": p.Name,
			}).Warning("could not parse package version, skipping")
			continue
		}

		featureVersion := database.FeatureVersion{
			Feature: database.Feature{
				Namespace: database.Namespace{
					Name:          u.Namespace,
					VersionFormat: rpm.ParserName,
				},
				Name: p.Name,
			},
			Version: version,
		}

		featureVersions = append(featureVersions, featureVersion)
	}

	return featureVersions
}

func compareTimestamp(date0 string, date1 string) int {
	// format: YYYY-MM-DD hh:mm
	switch {
	case date0 < date1:
		return -1
	case date0 > date1:
		return 1
	default:
		return 0
	}
}
