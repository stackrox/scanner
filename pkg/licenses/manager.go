package licenses

import (
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/scanner/pkg/mtls"
)

const (
	requestTimeout = 30 * time.Second
)

var (
	defaultTimeoutProvider = timeoutProvider{
		intervalBetweenPolls: 30 * time.Second,
		expiryGracePeriod:    time.Hour,
		expirySafetyBuffer:   time.Hour,
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
	expirySafetyBuffer   time.Duration
}

type manager struct {
	centralEndpoint string
	client          *http.Client
	timeouts        timeoutProvider

	licenseFetchAndValidateFunc licenseFetchAndValidateFunc

	validLicenseExists concurrency.Flag

	licenseExpiryLock sync.Mutex
	licenseExpiry     time.Time
}

// NewManager returns a new manager.
func NewManager(ctx concurrency.Waitable, centralEndpoint string) (Manager, error) {
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

	if timeouts.expiryGracePeriod == 0 || timeouts.expirySafetyBuffer == 0 || timeouts.intervalBetweenPolls == 0 {
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

func (m *manager) controlLoop(ctx concurrency.Waitable) {
	for {
		expiry, err := m.licenseFetchAndValidateFunc(ctx, m.centralEndpoint, m.client)
		if err != nil {
			log.WithError(err).Error("Failed to fetch license. Will retry...")
			if concurrency.WaitWithTimeout(ctx, m.timeouts.intervalBetweenPolls) {
				return
			}
			continue
		}
		log.Infof("Fetched new license that is valid until %s", expiry)
		var isDifferentLicense bool
		concurrency.WithLock(&m.licenseExpiryLock, func() {
			if !m.licenseExpiry.Equal(expiry) {
				isDifferentLicense = true
				m.licenseExpiry = expiry
			}
		})
		if isDifferentLicense {
			m.validLicenseExists.Set(true)
			concurrency.AfterFunc(time.Until(expiry.Add(m.timeouts.expiryGracePeriod)), func() {
				concurrency.WithLock(&m.licenseExpiryLock, func() {
					if m.licenseExpiry.Before(time.Now()) {
						m.validLicenseExists.Set(false)
					}
				})
			}, ctx)
		}

		// Start polling for a new license one hour before the old one expires.
		deadline := expiry.Add(-m.timeouts.expirySafetyBuffer)
		if deadline.After(time.Now()) {
			if concurrency.WaitWithDeadline(ctx, deadline) {
				return
			}
		} else {
			if concurrency.WaitWithTimeout(ctx, m.timeouts.intervalBetweenPolls) {
				return
			}
		}
	}
}
