package updater

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/clientconn"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/wellknowndirnames"
)

const (
	repoToCPEFilename = "rhelv2/repository-to-cpe.json"
)

var (
	slimUpdaterDir = filepath.Join(wellknowndirnames.WriteableDir, "slim-updater-artifacts.d")
)

// SlimUpdater updates the Scanner's definitions for scanner slim, contacting
// Sensor, instead of Central as the Updater does.
type SlimUpdater struct {
	interval        time.Duration
	lastUpdatedTime time.Time
	stopSig         *concurrency.Signal

	sensorClient           *http.Client
	repoToCPE              *repo2cpe.Mapping
	repoToCPELocalFilename string
	repoToCPEURL           string
}

// NewSlimUpdater creates and initialize a new slim updater.
func NewSlimUpdater(updaterConfig Config, sensorEndpoint string, repoToCPE *repo2cpe.Mapping) (*SlimUpdater, error) {
	// Get the most recent genesis dump UUID, and construct the update URL.
	uuid, err := getMostRecentGenesisDumpUUID()
	if err != nil {
		return nil, errors.Wrap(err, "getting genesis UUID")
	}
	repoToCPEURL, err := urlfmt.FullyQualifiedURL(
		strings.Join([]string{
			urlfmt.FormatURL(sensorEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash),
			"scanner/definitions",
		}, "/"),
		url.Values{
			"uuid": []string{uuid},
			"file": []string{repoToCPEFilename},
		})
	if err != nil {
		return nil, errors.Wrapf(err, "setting up sensor URL at %s", sensorEndpoint)
	}

	// Create sensor's HTTP client.
	sensorClient, err := clientconn.NewHTTPClient(
		mtls.SensorSubject, urlfmt.FormatURL(sensorEndpoint, urlfmt.NONE, urlfmt.NoTrailingSlash), defaultTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "creating sensor client")
	}

	// Set up the repo2cpe local filename and its directory.
	repoToCPELocalFilename := filepath.Join(slimUpdaterDir, filepath.FromSlash(repoToCPEFilename))
	if err := os.MkdirAll(filepath.Dir(repoToCPELocalFilename), 0700); err != nil {
		return nil, errors.Wrap(err, "creating slim updater output dir")
	}

	// Initialize the updater object.
	stopSig := concurrency.NewSignal()
	slimUpdater := &SlimUpdater{
		interval:               updaterConfig.Interval,
		stopSig:                &stopSig,
		sensorClient:           sensorClient,
		repoToCPE:              repoToCPE,
		repoToCPELocalFilename: repoToCPELocalFilename,
		repoToCPEURL:           repoToCPEURL,
	}

	return slimUpdater, nil
}

// RunForever starts the updater loop.
func (u *SlimUpdater) RunForever() {
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		if err := u.update(); err != nil {
			logrus.WithError(err).Error("slim update failed")
		}
		select {
		case <-t.C:
			continue
		case <-u.stopSig.Done():
			return
		}
	}

}

// Stop stops the updater loop.
func (u *SlimUpdater) Stop() {
	u.stopSig.Signal()
}

// update performs the slim updater steps.
func (u *SlimUpdater) update() error {
	logrus.Info("starting slim update")
	startTime := time.Now()
	fetched, err := fetchDumpFromURL(
		u.stopSig,
		u.sensorClient,
		u.repoToCPEURL,
		u.lastUpdatedTime,
		u.repoToCPELocalFilename,
	)
	if err != nil {
		return errors.Wrap(err, "fetching update from URL")
	}
	if !fetched {
		logrus.Info("already up-to-date, nothing to do")
		return nil
	}
	if err := u.repoToCPE.LoadFile(u.repoToCPELocalFilename); err != nil {
		return errors.Wrap(err, "failed to load repoToCPE mapping")
	}
	u.lastUpdatedTime = startTime
	logrus.Info("Finished slim update.")
	return nil
}
