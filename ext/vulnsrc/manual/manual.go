package manual

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnsrc"
)

var _ vulnsrc.Updater = (*updater)(nil)

type updater struct {
}

func init() {
	vulnsrc.RegisterUpdater("manual", &updater{})
}

// Vulnerabilities lists vulnerabilities which may not already exist in the feeds for other distros.
var Vulnerabilities = []database.Vulnerability{
	// Example valid and complete entry.
	//{
	//	Name:        "CVE-2022-12342",
	//	Description: "Description",
	//	Link:        "https://ubuntu.com/security/CVE-2022-12342",
	//	Severity:    database.CriticalSeverity,
	//	FixedIn: []database.FeatureVersion{
	//		{
	//			Feature: database.Feature{
	//				Name: "my-package",
	//				Namespace: database.Namespace{
	//					Name:          "ubuntu:22.04",
	//					VersionFormat: dpkg.ParserName,
	//				},
	//			},
	//			// Keep this version if the vulnerability is not fixed.
	//			Version: versionfmt.MaxVersion,
	//		},
	//	},
	//},
}

func (u updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, _ error) {
	log.WithField("package", "Manual Entries").Info("Start fetching vulnerabilities")

	resp.Vulnerabilities = Vulnerabilities
	return
}

func (u updater) Clean() {}
