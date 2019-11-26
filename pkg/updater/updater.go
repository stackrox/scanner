package updater

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/wellknowndirnames"
	"github.com/stackrox/scanner/pkg/wellknownkeys"
)

var (
	client = http.Client{
		Timeout: 5 * time.Minute,
	}

	diffDumpOutputPath = filepath.Join(wellknowndirnames.WriteableRoot, "diff-dump.zip")
	diffDumpScratchDir = filepath.Join(wellknowndirnames.WriteableRoot, "diff-dump-scratch")
)

const (
	ifModifiedSinceHeader = "If-Modified-Since"
)

type Updater struct {
	interval        time.Duration
	lastUpdatedTime time.Time
	downloadURL     string
	db              database.Datastore
	cpeDBUpdater    vulndump.InMemNVDCacheUpdater
	stopSig         *concurrency.Signal
}

func fetchDumpFromGoogleStorage(url string, lastUpdatedTime time.Time, outputPath string) (bool, error) {
	// First, head the URL to see when it was last modified.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, errors.Wrap(err, "constructing req")
	}
	req.Header.Set(ifModifiedSinceHeader, lastUpdatedTime.UTC().Format(http.TimeFormat))
	resp, err := client.Do(req)
	if err != nil {
		return false, errors.Wrap(err, "executing request")
	}
	defer utils.IgnoreError(resp.Body.Close)
	if resp.StatusCode == http.StatusNotModified {
		// Not modified
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, errors.Errorf("invalid response from google storage; got code %d", resp.StatusCode)
	}
	if err := httputil.ResponseToError(resp); err != nil {
		return false, err
	}
	outFile, err := os.Create(outputPath)
	if err != nil {
		return false, errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outFile.Close)
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "streaming response to file")
	}
	return true, nil
}

func (u *Updater) doUpdate() error {
	log.Info("Starting an update cycle")
	startTime := time.Now()
	if err := os.RemoveAll(diffDumpOutputPath); err != nil {
		return errors.Wrap(err, "removing diff dump output path")
	}
	if err := os.RemoveAll(diffDumpScratchDir); err != nil {
		return errors.Wrap(err, "removing diff dump scratch dir")
	}
	fetched, err := fetchDumpFromGoogleStorage(u.downloadURL, u.lastUpdatedTime, diffDumpOutputPath)
	if err != nil {
		return errors.Wrap(err, "fetching update from URL")
	}
	if !fetched {
		log.Info("No new update to fetch")
		return nil
	}
	if err := os.MkdirAll(diffDumpScratchDir, 0755); err != nil {
		return errors.Wrap(err, "creating scratch dir")
	}
	if err := vulndump.UpdateFromVulnDump(diffDumpOutputPath, diffDumpScratchDir, u.db, u.cpeDBUpdater); err != nil {
		return errors.Wrap(err, "updating from vuln dump")
	}
	u.lastUpdatedTime = startTime
	log.Info("Update cycle completed successfully!")
	return nil
}

func (u *Updater) doUpdateAndLogError() {
	if err := u.doUpdate(); err != nil {
		log.WithError(err).Error("Updater failed")
	}
}

func (u *Updater) runForever() {
	// Do an update at the very beginning.
	u.doUpdateAndLogError()
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			u.doUpdateAndLogError()
		case <-u.stopSig.Done():
			return
		}
	}
}

func getLastUpdatedTime(db database.Datastore) (time.Time, error) {
	val, err := db.GetKeyValue(wellknownkeys.VulnUpdateTimestampKey)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "getting last updated time from DB")
	}
	if val == "" {
		return time.Time{}, errors.New("no last updated time in the DB")
	}
	var dbTime time.Time
	if err := dbTime.UnmarshalText(bytes.TrimSpace([]byte(val))); err != nil {
		return time.Time{}, errors.Wrapf(err, "invalid timestamp in DB: %q", val)
	}
	return dbTime, nil
}

// Stop stops the updater.
func (u *Updater) Stop() {
	u.stopSig.Signal()
}

// New returns a new updater instance, and starts running the update daemon.
func New(config Config, db database.Datastore, cpeDBUpdater vulndump.InMemNVDCacheUpdater) (*Updater, error) {
	downloadURL, err := getRelevantDownloadURL()
	if err != nil {
		return nil, errors.Wrap(err, "getting relevant download URL")
	}
	lastUpdatedTime, err := getLastUpdatedTime(db)
	if err != nil {
		return nil, errors.Wrap(err, "getting last updated time from DB")
	}

	stopSig := concurrency.NewSignal()
	u := &Updater{
		interval:        config.Interval,
		downloadURL:     downloadURL,
		db:              db,
		cpeDBUpdater:    cpeDBUpdater,
		stopSig:         &stopSig,
		lastUpdatedTime: lastUpdatedTime,
	}
	go u.runForever()
	return u, nil
}
