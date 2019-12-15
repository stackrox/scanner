package updater

import (
	"archive/zip"
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/mtls"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/wellknownkeys"
)

const (
	ifModifiedSinceHeader = "If-Modified-Since"

	defaultTimeout = 5 * time.Minute
)

type Updater struct {
	lastUpdatedTime time.Time
	client          *http.Client

	interval           time.Duration
	downloadURL        string
	fetchIsFromCentral bool

	db           database.Datastore
	cpeDBUpdater vulndump.InMemNVDCacheUpdater

	stopSig *concurrency.Signal
}

func (u *Updater) fetchDumpFromURL() (io.ReadCloser, error) {
	// First, head the URL to see when it was last modified.
	req, err := http.NewRequestWithContext(concurrency.AsContext(u.stopSig), http.MethodGet, u.downloadURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "constructing req")
	}
	req.Header.Set(ifModifiedSinceHeader, u.lastUpdatedTime.UTC().Format(http.TimeFormat))
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing request")
	}
	defer utils.IgnoreError(resp.Body.Close)
	if resp.StatusCode == http.StatusNotModified {
		// Not modified
		return nil, nil
	}
	// If we're fetching from Central, 404s are okay.
	if u.fetchIsFromCentral && resp.StatusCode == http.StatusNotFound {
		log.Info("No vuln dumps were uploaded to Central")
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("invalid response from google storage; got code %d", resp.StatusCode)
	}
	if err := httputil.ResponseToError(resp); err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (u *Updater) doUpdate() error {
	log.Info("Starting an update cycle")
	startTime := time.Now()
	body, err := u.fetchDumpFromURL()
	if err != nil {
		return errors.Wrap(err, "fetching update from URL")
	}
	if body == nil {
		log.Info("No new update to fetch")
		return nil
	}
	defer utils.IgnoreError(body.Close)

	zipBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return errors.Wrap(err, "error reading from response body")
	}
	zipR, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return errors.Wrap(err, "error opening zip reader")
	}
	if err := vulndump.UpdateFromVulnDump(zipR, u.db, u.cpeDBUpdater); err != nil {
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

func (u *Updater) RunForever() {
	u.runForever()
}

// Stop stops the updater.
func (u *Updater) Stop() {
	u.stopSig.Signal()
}

// New returns a new updater instance, and starts running the update daemon.
func New(config Config, db database.Datastore, cpeDBUpdater vulndump.InMemNVDCacheUpdater) (*Updater, error) {
	downloadURL, isCentral, err := getRelevantDownloadURL(config, db)
	if err != nil {
		return nil, errors.Wrap(err, "getting relevant download URL")
	}

	client := &http.Client{
		Timeout:   defaultTimeout,
		Transport: proxy.RoundTripper(),
	}
	if isCentral {
		clientConfig, err := mtls.TLSClientConfigForCentral()
		if err != nil {
			return nil, errors.Wrap(err, "generating TLS client config for Central")
		}
		client.Transport = &http.Transport{
			TLSClientConfig: clientConfig,
		}
	}

	lastUpdatedTime, err := getLastUpdatedTime(db)
	if err != nil {
		return nil, errors.Wrap(err, "getting last updated time from DB")
	}

	stopSig := concurrency.NewSignal()
	u := &Updater{
		fetchIsFromCentral: isCentral,
		client:             client,
		interval:           config.Interval,
		downloadURL:        downloadURL,
		db:                 db,
		cpeDBUpdater:       cpeDBUpdater,
		stopSig:            &stopSig,
		lastUpdatedTime:    lastUpdatedTime,
	}
	return u, nil
}
