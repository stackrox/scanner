package e2etests

//lint:file-ignore U1000 These functions are used, but staticcheck is not smart about build tags.

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/urlfmt"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	scannerHTTPEndpointEnv = "SCANNER_ENDPOINT"
	scannerGRPCEndpointEnv = "SCANNER_GRPC_ENDPOINT"
)

func mustGetEnv(t *testing.T, key string) string {
	val := os.Getenv(key)
	require.NotEmpty(t, val, "No %s env found", key)
	return val
}

func getScannerHTTPEndpoint() string {
	return urlfmt.FormatURL(stringutils.OrDefault(os.Getenv(scannerHTTPEndpointEnv), "localhost:8080"), urlfmt.HTTPS, urlfmt.NoTrailingSlash)
}

func connectToScanner(t *testing.T) *grpc.ClientConn {
	gRPCEndpoint := stringutils.OrDefault(os.Getenv(scannerGRPCEndpointEnv), "localhost:8443")
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := grpc.NewClient(gRPCEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
	require.NoError(t, err)
	return conn
}

func scanImage(client v1.ImageScanServiceClient, req *v1.ScanImageRequest, t *testing.T) *v1.ScanImageResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scanImageResp, err := client.ScanImage(ctx, req)
	require.NoError(t, err)
	require.Equal(t, scanImageResp.GetStatus(), v1.ScanStatus_SUCCEEDED)
	return scanImageResp
}

func scanPublicDockerHubImage(client v1.ImageScanServiceClient, imageName string, uncertifiedRHEL bool, t *testing.T) *v1.ScanImageResponse {
	return scanImage(client, &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.RegistryData{
			Url: "https://registry-1.docker.io",
		},
		UncertifiedRHEL: uncertifiedRHEL,
	}, t)
}

func scanQuayStackRoxImage(client v1.ImageScanServiceClient, imageName string, uncertifiedRHEL bool, t *testing.T) *v1.ScanImageResponse {
	return scanImage(client, &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.RegistryData{
			Url:      "https://quay.io",
			Username: os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
			Password: os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		},
		UncertifiedRHEL: uncertifiedRHEL,
	}, t)
}

func scanGCRImage(client v1.ImageScanServiceClient, imageName string, t *testing.T) *v1.ScanImageResponse {
	return scanImage(client, &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.RegistryData{
			Url: "https://gcr.io",
		},
	}, t)
}
