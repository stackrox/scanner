package licenses

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/utils"
)

// These are copied from proto. We're just calling directly over HTTP for simplicity.
const (
	apiPath = "v1/licenses/getactive"
)

type licenseResponse struct {
	LicenseKey string `json:"licenseKey"`
}

func (m *manager) fetchFromCentral(ctx concurrency.Waitable) (string, error) {
	log.Infof("Attempting to fetch license from Central at %s", m.centralEndpoint)
	req, err := http.NewRequestWithContext(concurrency.AsContext(ctx), http.MethodGet, fmt.Sprintf("%s/%s", m.centralEndpoint, apiPath), nil)
	if err != nil {
		return "", errors.Wrap(err, "creating request")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "executing get request")
	}
	defer utils.IgnoreError(resp.Body.Close)
	// This endpoint always returns 200 on success.
	if resp.StatusCode != http.StatusOK {
		// Intentionally don't stick more from the response over here, want to make sure
		// not to accidentally log license keys.
		return "", errors.Wrapf(err, "got status code %d", resp.StatusCode)
	}
	var license licenseResponse
	err = json.NewDecoder(resp.Body).Decode(&license)
	if err != nil {
		return "", errors.Wrap(err, "JSON decoding license")
	}
	if license.LicenseKey == "" {
		return "", errors.New("Central returned status 200 but an empty license")
	}
	return license.LicenseKey, nil
}
