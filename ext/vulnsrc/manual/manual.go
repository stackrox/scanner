package manual

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnsrc"
)

var _ vulnsrc.Updater = (*updater)(nil)

type updater struct {
}

// Vulnerabilities lists vulnerabilities which may not already exist in the feeds for other distros.
var Vulnerabilities = []database.Vulnerability{}

func (u updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, _ error) {
	log.WithField("package", "Manual Entries").Info("Start fetching vulnerabilities")

	resp.Vulnerabilities = Vulnerabilities
	return
}

func (u updater) Clean() {}
