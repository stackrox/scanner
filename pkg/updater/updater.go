package updater

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/cache"
	"github.com/stackrox/scanner/pkg/mtls"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/wellknowndirnames"
	"github.com/stackrox/scanner/pkg/wellknownkeys"
)

var (
	diffDumpOutputPath = filepath.Join(wellknowndirnames.WriteableDir, "diff-dump.zip")
)

var (
	podName = os.Getenv("POD_NAME")
)

// Updater updates the Scanner's vulnerability data stores.
type Updater struct {
	lastUpdatedTime time.Time
	client          *http.Client

	interval    time.Duration
	downloadURL string

	db database.Datastore
	// Slice of application-level caches. This includes CPE data from NVD and CVE data from Kubernetes.
	caches []cache.Cache
	// RHELv2 repository-to-cpe.json file.
	repoToCPE *repo2cpe.Mapping

	stopSig *concurrency.Signal
}

type updateMode int

const (
	updateApplicationCachesAndPostgres updateMode = iota
	updateApplicationCachesOnly
)

func (u *Updater) doUpdate(mode updateMode) error {
	log.Info("Starting an update cycle")
	startTime := time.Now()
	if err := os.RemoveAll(diffDumpOutputPath); err != nil {
		return errors.Wrap(err, "removing diff dump output path")
	}
	fetched, err := fetchDumpFromURL(u.stopSig, u.client, u.downloadURL, u.lastUpdatedTime, diffDumpOutputPath)
	if err != nil {
		return errors.Wrap(err, "fetching update from URL")
	}
	if !fetched {
		log.Info("No new update to fetch")
		return nil
	}
	log.Info("TEST updater: UpdateFromVulnDump")
	var db database.Datastore
	if mode == updateApplicationCachesAndPostgres {
		db = u.db
	}
	if err := vulndump.UpdateFromVulnDump(diffDumpOutputPath, db, u.interval, podName, u.caches, u.repoToCPE); err != nil {
		return errors.Wrap(err, "updating from vuln dump")
	}
	if mode == updateApplicationCachesAndPostgres {
		u.lastUpdatedTime = startTime
	}
	log.Info("Update cycle completed successfully!")
	return nil
}

func (u *Updater) doUpdateAndLogError() {
	if err := u.doUpdate(updateApplicationCachesAndPostgres); err != nil {
		log.WithError(err).Error("Updater failed")
	}
}

func (u *Updater) runForever() {
	// Do an initial update as soon as we start.
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

// GetLastUpdatedTime returns the time when vulnerability definitions was last updated.
func GetLastUpdatedTime(db database.Datastore) (time.Time, error) {
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
func New(config Config, centralEndpoint string, db database.Datastore, repoToCPE *repo2cpe.Mapping, caches ...cache.Cache) (*Updater, error) {
	downloadURL, err := getRelevantDownloadURL(centralEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "getting relevant download URL")
	}

	client := newHTTPClient(proxy.RoundTripper())
	clientConfig, err := mtls.TLSClientConfigForCentral()
	if err != nil {
		return nil, errors.Wrap(err, "generating TLS client config for Central")
	}
	client.Transport = &http.Transport{
		TLSClientConfig: clientConfig,
		// We are pulling the definitions bundle, which is already compressed.
		DisableCompression: true,
		// Values are taken from http.DefaultTransport, Go 1.17.3
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	lastUpdatedTime, err := GetLastUpdatedTime(db)
	if err != nil {
		return nil, errors.Wrap(err, "getting last updated time from DB")
	}

	stopSig := concurrency.NewSignal()
	u := &Updater{
		client:          client,
		interval:        config.Interval,
		downloadURL:     downloadURL,
		db:              db,
		caches:          caches,
		repoToCPE:       repoToCPE,
		stopSig:         &stopSig,
		lastUpdatedTime: lastUpdatedTime,
	}
	return u, nil
}

// UpdateApplicationCachesOnly updates the application caches and not the Postgres DB.
func (u *Updater) UpdateApplicationCachesOnly() {
	if err := u.doUpdate(updateApplicationCachesOnly); err != nil {
		log.WithError(err).Error("Updater failed")
	}
}

// RunForever runs the updater "forever".
func (u *Updater) RunForever() {
	u.runForever()
}
