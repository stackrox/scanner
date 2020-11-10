// +build e2e_nolicense

package e2etests

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stackrox/scanner/pkg/licenses"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	timeout = 10 * time.Second
)

var (
	httpClient = &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
)

func TestScannerRejectsLicenseHTTP(t *testing.T) {
	endpoint := getScannerHTTPEndpoint(t)

	for _, urlAndMethod := range []struct {
		method string
		url    string
	}{
		{
			http.MethodGet,
			"ping",
		},
		{
			http.MethodPost,
			"image",
		},
		{
			http.MethodGet,
			"sha/sha123",
		},
		{
			http.MethodGet,
			"image/docker.io/stackrox/123",
		},
		{
			http.MethodGet,
			"image/docker.io/namespace/stackrox/123",
		},
	} {
		for _, root := range []string{"clairify", "scanner"} {
			url := fmt.Sprintf("%s/%s", root, urlAndMethod.url)
			t.Run(fmt.Sprintf("%s/%s", url, urlAndMethod.method), func(t *testing.T) {
				req, err := http.NewRequest(urlAndMethod.method, fmt.Sprintf("%s/%s", endpoint, url), nil)
				require.NoError(t, err)
				resp, err := httpClient.Do(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				respBytes, err := ioutil.ReadAll(resp.Body)
				require.NoError(t, err)

				var structuredResp struct {
					Message string `json:"message"`
				}
				require.NoError(t, json.Unmarshal(respBytes, &structuredResp), string(respBytes))
				assert.Equal(t, licenses.ErrNoValidLicense.Error(), structuredResp.Message)
			})
		}
	}
}

func TestScannerRejectsLicenseGRPC(t *testing.T) {
	conn := connectToScanner(t)
	pingClient := v1.NewPingServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := pingClient.Ping(ctx, &v1.Empty{})
	require.NoError(t, err)

	scanClient := v1.NewScanServiceClient(conn)

	methods := []func(ctx context.Context, scanClient v1.ScanServiceClient) error{
		func(ctx context.Context, scanClient v1.ScanServiceClient) error {
			_, err := scanClient.GetLanguageLevelComponents(ctx, &v1.GetLanguageLevelComponentsRequest{})
			return err
		},
		func(ctx context.Context, scanClient v1.ScanServiceClient) error {
			_, err := scanClient.GetScan(ctx, &v1.GetScanRequest{})
			return err
		},
		func(ctx context.Context, scanClient v1.ScanServiceClient) error {
			_, err := scanClient.ScanImage(ctx, &v1.ScanImageRequest{})
			return err
		},
		func(ctx context.Context, scanClient v1.ScanServiceClient) error {
			_, err := scanClient.GetVulnerabilities(ctx, &v1.GetVulnerabilitiesRequest{})
			return err
		},
	}
	assert.Equal(t, len(methods), reflect.ValueOf(scanClient).NumMethod(), "New methods have been added to the scan service, but they are not tested!")

	for i, method := range methods {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			err := method(ctx, scanClient)
			require.Error(t, err)
			assert.Contains(t, err.Error(), licenses.ErrNoValidLicense.Error())
		})
	}
}
