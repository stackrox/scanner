package tests

import (
	"context"
	"crypto/tls"
	"os"
	"testing"

	"github.com/stackrox/rox/pkg/stringutils"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func connectToScanner(t *testing.T) *grpc.ClientConn {
	gRPCEndpoint := stringutils.OrDefault(os.Getenv("SCANNER_GRPC_ENDPOINT"), "localhost:8081")
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := grpc.DialContext(context.Background(), gRPCEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
	require.NoError(t, err)
	return conn
}

func scanPublicDockerHubImage(client v1.ScanServiceClient, imageName string, t *testing.T) *v1.ScanImageResponse {
	scanImageResp, err := client.ScanImage(context.Background(), &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.ScanImageRequest_RegistryData{
			Url: "https://registry-1.docker.io",
		},
	})
	require.NoError(t, err)
	require.Equal(t, scanImageResp.GetStatus(), v1.ScanStatus_SUCCEEDED)
	return scanImageResp
}
