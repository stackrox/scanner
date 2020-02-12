/// build e2e-nolicense

package e2etests

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/licenses"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	httpClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
)

func TestScannerRejectsLicense(t *testing.T) {
	// First, HTTP
	endpoint := getScannerHTTPEndpoint(t)
	cli := client.New(endpoint, true)
	require.NoError(t, cli.Ping())

	for _, urlAndMethod := range []struct {
		method string
		url    string
	}{
		{
			http.MethodPost,
			"scanner/image",
		},
	} {
		t.Run(fmt.Sprintf("%+v", urlAndMethod), func(t *testing.T) {
			req, err := http.NewRequest(urlAndMethod.method, fmt.Sprintf("%s/%s", endpoint, urlAndMethod.url), nil)
			require.NoError(t, err)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			assert.Equal(t, resp.StatusCode, http.StatusInternalServerError)
			respBytes, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)

			var structuredResp struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(respBytes, &structuredResp))
			assert.Equal(t, licenses.ErrNoValidLicense.Error(), structuredResp.Message)
		})
	}
}
