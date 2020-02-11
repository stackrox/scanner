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
	defaultTimeout = 30 * time.Second

	intervalBetweenSuccessivePolls = 30 * time.Second

	licenseExpiryGracePeriod = time.Hour
)

// Manager manages licensing from the scanner's PoV.
type Manager interface {
	ValidLicenseExists() bool
}

type manager struct {
	centralEndpoint    string
	client             *http.Client
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
	m := &manager{
		centralEndpoint: centralEndpoint,
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &http.Transport{TLSClientConfig: clientConf}},
	}
	go m.controlLoop(ctx)
	return m, nil
}

func (m *manager) ValidLicenseExists() bool {
	return m.validLicenseExists.Get()
}

func (m *manager) fetchAndValidateLicense(ctx concurrency.Waitable) (time.Time, error) {
	license, err := m.fetchFromCentral(ctx)
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
		expiry, err := m.fetchAndValidateLicense(ctx)
		if err != nil {
			log.WithError(err).Error("Failed to fetch license. Will retry...")
			if concurrency.WaitWithTimeout(ctx, intervalBetweenSuccessivePolls) {
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
			concurrency.AfterFunc(time.Until(expiry.Add(licenseExpiryGracePeriod)), func() {
				concurrency.WithLock(&m.licenseExpiryLock, func() {
					if m.licenseExpiry.Before(time.Now()) {
						m.validLicenseExists.Set(false)
					}
				})
			}, ctx)
		}

		// Start polling for a new license one hour before the old one expires.
		deadline := expiry.Add(-1 * time.Hour)
		if deadline.After(time.Now()) {
			if concurrency.WaitWithDeadline(ctx, deadline) {
				return
			}
		} else {
			if concurrency.WaitWithTimeout(ctx, intervalBetweenSuccessivePolls) {
				return
			}
		}
	}
}
