package tests

import (
	"context"
	"crypto/tls"
	"testing"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGRPCScanImage(t *testing.T) {
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := grpc.DialContext(context.Background(), "localhost:8081", grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
	require.NoError(t, err)

	client := v1.NewScanServiceClient(conn)
	scanImageResp, err := client.ScanImage(context.Background(), &v1.ScanImageRequest{
		Image: "nginx",
		Registry: &v1.ScanImageRequest_RegistryData{
			Url:      "https://registry-1.docker.io",
			Username: "",
			Password: "",
		},
	})
	require.NoError(t, err)

	getScanResp, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: &v1.ImageSpec{Image: scanImageResp.Image.GetImage()},
	})
	require.NoError(t, err)
	assert.NotZero(t, len(getScanResp.GetImage().GetFeatures()))
}
