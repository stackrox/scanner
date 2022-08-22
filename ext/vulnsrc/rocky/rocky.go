// Package rocky implements a vulnerability source updater using
// RLSA (Rocky Linux Security Advisories).
package rocky

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/httputil"
)

const (
	url        = "https://errata.rockylinux.org/api/advisories"
	linkFormat = "https://errata.rockylinux.org/%s"
)

var (
	rpmRegexp        = regexp.MustCompile(`(?P<name>.*)-(?P<version>[^\-]+\-[^\-]+)\.(?P<basearch>[^.]+)\.rpm$`)
	rpmReleaseRegexp = regexp.MustCompile(`.*\.el(?P<version>[\d]+)`)
)

type jsonData struct {
	Advisories []jsonAdvisory `json:"advisories"`
}

type jsonAdvisory struct {
	Type             string   `json:"type"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	AffectedProducts []string `json:"affectedProducts"`
	Severity         string   `json:"severity"`
	CVEs             []string `json:"cves"`
	RPMs             []string `json:"rpms"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("rocky", &updater{})
}

func (u *updater) Update(datastore vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Rocky").Info("Start fetching vulnerabilites")

	// Download JSON
	r, err := httputil.GetWithUserAgent(url)
	if err != nil {
		log.WithError(err).Error("could not download Rocky's update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithField("StatusCode", r.StatusCode).Error("Failed to update Rocky")
		return resp, commonerr.ErrCouldNotDownload
	}

	// Parse JSON
	resp, err = buildResponse(r.Body)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (u *updater) Clean() {}

func buildResponse(jsonReader io.Reader) (resp vulnsrc.UpdateResponse, err error) {
	// Unmarshal JSON
	var data jsonData
	err = json.NewDecoder(jsonReader).Decode(&data)
	if err != nil {
		log.WithError(err).Error("could not unmarshal Rocky's JSON")
		return resp, commonerr.ErrCouldNotParse
	}

	// Extract vulnerability data from Rocky's JSON schema.
	resp.Vulnerabilities = parseRockyJSON(&data)

	return resp, nil
}

func parseRockyJSON(data *jsonData) []database.Vulnerability {
	var vulnerabilities []database.Vulnerability

	for _, advisory := range data.Advisories {
		if !strings.EqualFold(advisory.Type, "security") {
			continue
		}

		vulnName := advisory.Name

		subCVEs := make([]string, 0, len(advisory.CVEs))
		for _, cve := range advisory.CVEs {
			cveID := cve[strings.LastIndex(cve, ":::")+3:]
			if strings.HasPrefix(cveID, "CVE-") {
				subCVEs = append(subCVEs, cveID)
			}
		}

		vuln := database.Vulnerability{
			Name:        vulnName,
			Link:        fmt.Sprintf(linkFormat, vulnName),
			Severity:    normalizeSeverity(advisory.Severity),
			Description: advisory.Description,
			SubCVEs:     subCVEs,
		}

		for _, rpmName := range advisory.RPMs {
			// FixMe: This is not ideal and likely error prone.
			// Better if api carried more detailed data.
			r := rpmRegexp.FindStringSubmatch(rpmName)
			if len(r) != 4 {
				continue
			}

			pkgName := r[1]
			pkgVersion := r[2]

			r = rpmReleaseRegexp.FindStringSubmatch(pkgVersion)
			if len(r) != 2 {
				continue
			}

			releaseVersion := r[1]

			// Create and add the feature version
			pkg := database.FeatureVersion{

				Feature: database.Feature{
					Name: pkgName,
					Namespace: database.Namespace{
						Name:          "rocky:" + releaseVersion,
						VersionFormat: rpm.ParserName,
					},
				},
				Version: pkgVersion,
			}
			vuln.FixedIn = append(vuln.FixedIn, pkg)
		}

		// Store the vulnerability
		vulnerabilities = append(vulnerabilities, vuln)

	}

	return vulnerabilities
}

func normalizeSeverity(severity string) database.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", severity).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}
