package licenses

import (
	"io/ioutil"
	"net/http"
<<<<<<< HEAD
=======
	"os"
	"sync"
>>>>>>> c092ea6... Chart changes
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/scanner/pkg/mtls"
)

const (
	requestTimeout = 30 * time.Second

	secretLicensePath = "/run/secrets/stackrox.io/ef97c1c1-0027-4f4a-b398-ca49fff5be17/license.lic"
)

var (
	defaultTimeoutProvider = timeoutProvider{
		intervalBetweenPolls: 30 * time.Second,
		expiryGracePeriod:    time.Hour,
	}
)

// Manager manages licensing from the scanner's PoV.
type Manager interface {
	ValidLicenseExists() bool
}

type licenseFetchAndValidateFunc func(ctx concurrency.Waitable, centralEndpoint string, client *http.Client) (expiry time.Time, err error)

type timeoutProvider struct {
	intervalBetweenPolls time.Duration
	expiryGracePeriod    time.Duration
}

type manager struct {
	centralEndpoint string
	client          *http.Client
	timeouts        timeoutProvider

	licenseFetchAndValidateFunc licenseFetchAndValidateFunc

	validLicenseExists concurrency.Flag

	licenseExpiry time.Time
}

type secretBasedManager struct {
	expiry time.Time
}

func (m *secretBasedManager) ValidLicenseExists() bool {
	return m.expiry.After(time.Now())
}

func maybeInitializeFromSecret() Manager {
	licenseBytes, err := ioutil.ReadFile(secretLicensePath)
	if err != nil {
		// Avoid logging the error so as to not leak the file name.
		log.Debug("no license found through secret")
		return nil
	}
	expiry, err := validate(string(licenseBytes))
	if err != nil {
		log.WithError(err).Debug("invalid license found from secret")
		return nil
	}
	// The secret-based manager path will only be used in dev when we are running scanner standalone.
	// It will NOT be advertised to customers. For simplicity here, don't bother polling the secret or anything.
	// Just bounce scanner. This code path will basically only be hit when the dev license expires.
	time.AfterFunc(time.Until(expiry), func() {
		log.Debug("license in secret is expiring, bouncing scanner...")
		os.Exit(1)
	})
	log.Debugf("Initializing license from secret. Expiry: %s", expiry)
	return &secretBasedManager{expiry: expiry}
}

// NewManager returns a new manager.
func NewManager(ctx concurrency.Waitable, centralEndpoint string) (Manager, error) {
	secretBased := maybeInitializeFromSecret()
	if secretBased != nil {
		return secretBased, nil
	}

	if centralEndpoint == "" {
		centralEndpoint = "https://central.stackrox"
	}
	centralEndpoint, err := urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)
	if err != nil {
		return nil, errors.Wrap(err, "formatting central endpoint")
	}
	clientConf, err := mtls.TLSClientConfigForCentral()
	if err != nil {
		return nil, errors.Wrap(err, "creating client")
	}
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: clientConf},
	}
	return newManager(ctx, centralEndpoint, fetchLicenseFromCentralAndValidate, client, defaultTimeoutProvider)
}

func newManager(ctx concurrency.Waitable, formattedCentralEndpoint string, validateFunc licenseFetchAndValidateFunc, client *http.Client,
	timeouts timeoutProvider) (Manager, error) {

	if timeouts.expiryGracePeriod == 0 || timeouts.intervalBetweenPolls == 0 {
		return nil, errors.Errorf("invalid timeouts: %v", timeouts)
	}

	m := &manager{
		centralEndpoint:             formattedCentralEndpoint,
		client:                      client,
		licenseFetchAndValidateFunc: validateFunc,
		timeouts:                    timeouts,
	}
	go m.controlLoop(ctx)
	return m, nil
}

func (m *manager) ValidLicenseExists() bool {
	return m.validLicenseExists.Get()
}

func fetchLicenseFromCentralAndValidate(ctx concurrency.Waitable, centralEndpoint string, client *http.Client) (time.Time, error) {
	license, err := fetchFromCentral(ctx, centralEndpoint, client)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "fetching license from central")
	}
	expiry, err := validate(license)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "validating fetched license")
	}
	return expiry, nil
}

func expiryOrIntervalLater(expiry time.Time, interval time.Duration) time.Time {
	now := time.Now()
	if expiry.After(now) {
		return expiry
	}
	return now.Add(interval)
}

func (m *manager) reconcileExpiryAndFlag() {
	m.validLicenseExists.Set(m.licenseExpiry.Add(m.timeouts.expiryGracePeriod).After(time.Now()))
}

func (m *manager) controlLoop(ctx concurrency.Waitable) {
	for {
		m.reconcileExpiryAndFlag()

		expiry, err := m.licenseFetchAndValidateFunc(ctx, m.centralEndpoint, m.client)
		if err != nil {
			log.WithError(err).Error("Failed to fetch license. Will retry...")
			if concurrency.WaitWithTimeout(ctx, m.timeouts.intervalBetweenPolls) {
				return
			}
			continue
		}
		log.Infof("Fetched license that is valid until %s.", expiry)

		m.licenseExpiry = expiry
		m.reconcileExpiryAndFlag()

		if concurrency.WaitWithDeadline(ctx, expiryOrIntervalLater(m.licenseExpiry, m.timeouts.intervalBetweenPolls)) {
			return
		}
	}
}
