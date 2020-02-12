package licenses

import (
	"net/http"
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
