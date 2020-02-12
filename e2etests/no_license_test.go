/// +build e2e-nolicense

package e2etests

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stretchr/testify/require"
)

var (
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

func TestScannerRejectsLicense(t *testing.T) {
	// First, HTTP
	endpoint := getScannerHTTPEndpoint()

	cli := client.New(getScannerHTTPEndpoint(), true)
	require.NoError(t, cli.Ping())

	for _, urlAndMethod := range []struct {
		url    string
		method string
	}{
		{
			http.MethodPost,
			"scanner/image",
		},
	} {
		req, err := http.NewRequest(urlAndMethod.method, fmt.Sprintf("%s/%s", endpoint, urlAndMethod.url), nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, resp.StatusCode, http.StatusInternalServerError)
	}
}
