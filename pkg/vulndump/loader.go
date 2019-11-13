package vulndump

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mholt/archiver"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/wellknownkeys"
)

// InMemNVDCacheUpdater is a callback that updates the inmem NVD cache from a directory of extracted nvd definitions.
type InMemNVDCacheUpdater func(nvdDefinitionsDir string) error

func parseTime(marshaled []byte) (time.Time, error) {
	var t time.Time
	if err := t.UnmarshalText(bytes.TrimSpace(marshaled)); err != nil {
		return time.Time{}, errors.Wrapf(err, "invalid timestamp %s", string(marshaled))
	}
	return t, nil
}

func filterVulns(dbUpdatedTime time.Time, wrappedVulnsPath string) ([]database.Vulnerability, error) {
	f, err := os.Open(wrappedVulnsPath)
	if err != nil {
		return nil, errors.Wrap(err, "invalid file path for wrapped vulns")
	}
	var wrappedVulns []WrappedVulnerability
	if err := json.NewDecoder(f).Decode(&wrappedVulns); err != nil {
		return nil, errors.Wrap(err, "JSON decoding failed")
	}
	var filteredVulns []database.Vulnerability
	for _, wrappedVuln := range wrappedVulns {
		if !dbUpdatedTime.IsZero() && (!wrappedVuln.LastUpdatedTime.After(dbUpdatedTime)) {
			continue
		}
		filteredVulns = append(filteredVulns, wrappedVuln.Vulnerability)
	}
	return filteredVulns, nil
}

// UpdateFromVulnDump updates the definitions (both in the DB and in the inMemUpdater) from the given tar file.
// The structure of the vuln dump is as follows. It is a .tar.gz containing:
// - a file called TIMESTAMP, which contains the time (serialized using MarshalText of time.Time).
// - a directory called nvd, which contains one JSON file per year with the NVD dump.
// - a file called vulns_from_feeds.json which contains a JSON serialized []WrappedVulnerability array.
func UpdateFromVulnDump(tarGZPath string, db database.Datastore, inMemUpdater InMemNVDCacheUpdater) error {
	if !strings.HasSuffix(tarGZPath, ".tar.gz") {
		return errors.Errorf("invalid path %q: only .tar.gz files are supported", tarGZPath)
	}
	destination, err := ioutil.TempDir("", "vuln-dump-extracted")
	if err != nil {
		return errors.Wrap(err, "failed to create temp dir for extracted vuln dump")
	}
	defer func() {
		_ = os.RemoveAll(destination)
	}()

	log.WithField("dir", destination).Info("Extracting vuln definitions into temp dir")
	if err := archiver.DefaultTarGz.Unarchive(tarGZPath, destination); err != nil {
		return errors.Wrap(err, "failed to unarchive tar gz file")
	}

	dumpTSBytes, err := ioutil.ReadFile(filepath.Join(destination, "TIMESTAMP"))
	if err != nil {
		return errors.Wrap(err, "couldn't read the timestamp")
	}
	dumpTime, err := parseTime(dumpTSBytes)
	if err != nil {
		return errors.Wrap(err, "invalid TS in dump")
	}
	dbTSString, err := db.GetKeyValue(wellknownkeys.VulnUpdateTimestampKey)
	if err != nil {
		return errors.Wrap(err, "failed to get key value from DB")
	}
	var dbTime time.Time
	// First update.
	if dbTSString != "" {
		dbTime, err = parseTime([]byte(dbTSString))
		if err != nil {
			return errors.Wrap(err, "invalid TS in DB")
		}
	}
	if !dbTime.IsZero() {
		if dumpTime.Before(dbTime) || dumpTime.Equal(dbTime) {
			logrus.Info("DB is up to date with this dump. Nothing to do here.")
			return nil
		}
	}
	if err := inMemUpdater(filepath.Join(destination, "nvd")); err != nil {
		return errors.Wrap(err, "couldn't update in mem NVD copy")
	}
	filteredVulns, err := filterVulns(dbTime, filepath.Join(destination, "vulns_from_feeds.json"))
	if err != nil {
		return errors.Wrap(err, "filtering vulns")
	}
	logrus.Infof("Inserting %d vulns into the DB", len(filteredVulns))
	if err := db.InsertVulnerabilities(filteredVulns); err != nil {
		return errors.Wrap(err, "inserting vulns into the DB")
	}
	logrus.Info("Done inserting vulns into the DB")
	if err := db.InsertKeyValue(wellknownkeys.VulnUpdateTimestampKey, string(dumpTSBytes)); err != nil {
		return errors.Wrap(err, "couldn't update timestamp key in DB")
	}
	return nil
}
