package vulndump

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mholt/archiver"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/fileutils"
	"github.com/stackrox/rox/pkg/timeutil"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/wellknownkeys"
)

var (
	// This lets us do some basic validation on the dumps, since no dumps were created before this date.
	// Therefore, if a dump has a start time before this timestamp, its start timestamp MUST be the zero time,
	// and its end timestamp MUST be after this time.
	earliestDump = timeutil.MustParse(time.RFC3339, "2019-11-19T00:00:00Z")
)

// InMemNVDCacheUpdater is a callback that updates the inmem NVD cache from a directory of extracted nvd definitions.
type InMemNVDCacheUpdater func(nvdDefinitionsDir string) error

func loadVulns(osVulnsFile io.ReadCloser) ([]database.Vulnerability, error) {
	defer utils.IgnoreError(osVulnsFile.Close)

	var vulns []database.Vulnerability
	if err := json.NewDecoder(osVulnsFile).Decode(&vulns); err != nil {
		return nil, errors.Wrap(err, "JSON decoding failed")
	}
	return vulns, nil
}

func openFileInZip(zipR *zip.ReadCloser, name string) (io.ReadCloser, error) {
	for _, file := range zipR.File {
		if file.Name == name {
			return file.Open()
		}
	}
	return nil, errors.Errorf("file %q not found in zip", name)
}

func validateAndLoadManifest(f io.ReadCloser) (*Manifest, error) {
	defer utils.IgnoreError(f.Close)
	var m Manifest
	err := json.NewDecoder(f).Decode(&m)
	if err != nil {
		return nil, errors.Wrap(err, "decoding manifest")
	}
	// This is a "genesis" dump. This will only get loaded in CI, never in prod.
	// Make sure that the time goes from 0->after earliestDump.
	if m.Since.Before(earliestDump) {
		if !m.Since.IsZero() {
			return nil, errors.Errorf("invalid since time in manifest: %s; it is before our known earliest dump, but not the zero time!", m.Since)
		}
		if m.Until.Before(earliestDump) {
			return nil, errors.Errorf("invalid until time in manifest: %s; the dump is a genesis dump, but ends before our earliestDump time!", m.Until)
		}
	} else {
		// Not a genesis dump. This path will be hit during regular updates.
		// Make sure it starts after earliestDump->some time after that.
		if !m.Since.After(earliestDump) {
			return nil, errors.Errorf("unexpected dump: not a genesis dump, but starts before our earliest known dump (at %s)", m.Since)
		}
		if !m.Until.After(m.Since) {
			return nil, errors.Errorf("unexpected dump: m.Until (%s) is not after m.Since (%s)", m.Until, m.Since)
		}
	}
	return &m, nil
}

func determineWhetherToUpdate(db database.Datastore, manifest *Manifest) (bool, error) {
	val, err := db.GetKeyValue(wellknownkeys.VulnUpdateTimestampKey)
	if err != nil {
		return false, errors.Wrap(err, "getting last update timestamp from DB")
	}
	// If the val is empty, that means this is a first update.
	// That means that we MUST make sure that the dump is a genesis dump.
	if val == "" {
		if !manifest.Since.IsZero() {
			return false, errors.New("DB is empty, but this dump is NOT a genesis dump. We NEED to load a genesis dump first.")
		}
		// Nothing in the DB, and this is a genesis dump. Let's update.
		return true, nil
	}

	// Not a first update. We update only if the manifest contains updates from after the most recent
	// update in the DB.
	var dbTime time.Time
	if err := dbTime.UnmarshalText(bytes.TrimSpace([]byte(val))); err != nil {
		return false, errors.Wrapf(err, "invalid timestamp in DB: %q", val)
	}
	return manifest.Until.After(dbTime), nil
}

// UpdateFromVulnDump updates the definitions (both in the DB and in the inMemUpdater) from the given zip file.
// Check the well_known_names.go file for the manifest of the ZIP file.
// The caller is responsible for providing a path to a scratchDir, which MUST be an empty, but existing, directory.
// This function will delete the directory before returning.
func UpdateFromVulnDump(zipPath string, scratchDir string, db database.Datastore, inMemUpdater InMemNVDCacheUpdater) error {
	log.Infof("Attempting to update from vuln dump at %q", zipPath)
	if !fileutils.DirExistsAndIsEmpty(scratchDir) {
		return errors.Errorf("scratchDir %q invalid: must be an empty directory", scratchDir)
	}
	defer func() {
		if err := os.RemoveAll(scratchDir); err != nil {
			log.WithError(err).WithField("dir", scratchDir).Warn("Failed to clean up scratch dir")
		}
	}()

	if filepath.Ext(zipPath) != ".zip" {
		return errors.Errorf("invalid path %q: only .zip files are supported", zipPath)
	}

	zipR, err := zip.OpenReader(zipPath)
	if err != nil {
		return errors.Wrap(err, "opening zip file")
	}
	var zipFileClosed bool
	defer func() {
		if !zipFileClosed {
			_ = zipR.Close()
		}
	}()

	log.Info("Loading manifest")
	manifestFile, err := openFileInZip(zipR, ManifestFileName)
	if err != nil {
		return errors.Wrap(err, "opening manifest file")
	}
	manifest, err := validateAndLoadManifest(manifestFile)
	if err != nil {
		return errors.Wrap(err, "loading/validating manifest")
	}
	log.Info("Loaded manifest")
	shouldUpdate, err := determineWhetherToUpdate(db, manifest)
	if err != nil {
		return errors.Wrap(err, "determining whether to update")
	}
	if !shouldUpdate {
		log.Infof("DB already contains all the vulns in the dump at %q. Nothing to do here!", zipPath)
		return nil
	}
	log.Info("Running the update.")

	log.Info("Loading OS vulns...")
	osVulnsFile, err := openFileInZip(zipR, OSVulnsFileName)
	if err != nil {
		return errors.Wrap(err, "opening os vulns file")
	}
	osVulns, err := loadVulns(osVulnsFile)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns")
	}
	log.Infof("Done loading OS vulns. There are %d vulns to insert into the DB", len(osVulns))
	if err := db.InsertVulnerabilities(osVulns); err != nil {
		return errors.Wrap(err, "inserting vulns into the DB")
	}
	log.Info("Done inserting vulns into the DB")

	// Explicitly close the zip file because the
	// archiver.Extract function below calls zip.Open again.
	_ = zipR.Close()
	zipFileClosed = true

	if inMemUpdater != nil {
		if err := archiver.DefaultZip.Extract(zipPath, NVDDirName, scratchDir); err != nil {
			log.WithError(err).Error("Failed to extract NVD dump from ZIP")
		}
		if err := inMemUpdater(filepath.Join(scratchDir, "nvd")); err != nil {
			return errors.Wrap(err, "couldn't update in mem NVD copy")
		}
	}
	marshaledDumpTS, err := manifest.Until.MarshalText()
	// Really shouldn't happen because we literally just unmarshaled it.
	utils.Must(err)
	if err := db.InsertKeyValue(wellknownkeys.VulnUpdateTimestampKey, string(marshaledDumpTS)); err != nil {
		return errors.Wrap(err, "couldn't update timestamp key in DB")
	}
	return nil
}
