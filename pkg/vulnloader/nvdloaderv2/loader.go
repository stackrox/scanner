package nvdloaderv2

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/facebookincubator/nvdtools/cveapi/nvd/schema"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

const (
	baseURL = `https://services.nvd.nist.gov/rest/json/cves/2.0`
)

var (
	client = http.Client{
		Timeout:   2 * time.Minute,
		Transport: proxy.RoundTripper(),
	}
)

func init() {
	vulnloader.RegisterLoader(vulndump.NVDDirName, &loader{})
}

var _ vulnloader.Loader = (*loader)(nil)

type loader struct {}

// DownloadFeedsToPath downloads the NVD CVEs to the given path.
// If this function is successful, it will fill the directory with
// one json file for each year of NVD data.
func (l *loader) DownloadFeedsToPath(s string) error {
	// Just do a basic query at the start.
	// This will help us determine the default resultsPerPage,
	// which is recommended to use. It will also use startIndex=0
	// automatically.
	resp, err := client.Get(baseURL)
	if err != nil {
		return errors.Wrap(err, "fetching initial NVD API results")
	}
	apiResponse, err := parse(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "parsing body for API request to %q", baseURL)
	}
	
}

func parse(body io.ReadCloser) (*schema.CVEAPIJSON20, error) {
	defer func() {
		_ = body.Close()
	}()

	apiResponse := new(schema.CVEAPIJSON20)
	if err := json.NewDecoder(body).Decode(apiResponse); err != nil {
		return nil, errors.Wrap(err, "decoding API response")
	}

	return apiResponse, nil
}
