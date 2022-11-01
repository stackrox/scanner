package manual

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/vulnsrc"
)

var _ vulnsrc.Updater = (*updater)(nil)

type updater struct {
}

// Vulnerabilities lists vulnerabilities which may not already exist in the feeds for other distros.
var Vulnerabilities = []database.Vulnerability{
	{
		Name: "CVE-2022-3602",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "X.509 Email Address Buffer Overflow",
		Link:        "https://ubuntu.com/security/CVE-2022-3786",
		Severity:    "Important",
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.2-0ubuntu1.7",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"CVSSv2": map[string]interface{}{
					"ExploitabilityScore": 0.0,
					"ImpactScore":         0.0,
					"Score":               0.0,
					"Vectors":             "",
				},
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 2.8,
					"ImpactScore":         5.9,
					"Score":               8.8,
					"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
				},
			},
		},
	},
	{
		Name: "CVE-2022-3786",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "X.509 Email Address Buffer Overflow",
		Link:        "https://ubuntu.com/security/CVE-2022-3786",
		Severity:    "Important",
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.2-0ubuntu1.7",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"CVSSv2": map[string]interface{}{
					"ExploitabilityScore": 0.0,
					"ImpactScore":         0.0,
					"Score":               0.0,
					"Vectors":             "",
				},
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 3.9,
					"ImpactScore":         3.6,
					"Score":               7.5,
					"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				},
			},
		},
	},
}

func (u updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, _ error) {
	log.WithField("package", "Manual Entries").Info("Start fetching vulnerabilities")

	resp.Vulnerabilities = Vulnerabilities
	return
}

func (u updater) Clean() {}
