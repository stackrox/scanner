package tests

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/stringutils"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	scannerGRPCEndpointEnv = "SCANNER_GRPC_ENDPOINTT"
	dockerIOUsernameEnv    = "DOCKER_IO_PULL_USERNAME"
	dockerIOPasswordEnv    = "DOCKER_IO_PULL_PASSWORD"
)

var (
	maybeGetFromKeyChain func() (string, string)
)

func mustGetDockerCredentials(t *testing.T) (string, string) {
	user, pass := maybeGetFromKeyChain()
	if stringutils.AllNotEmpty(user, pass) {
		return user, pass
	}
	return mustGetEnv(dockerIOUsernameEnv, t), mustGetEnv(dockerIOPasswordEnv, t)
}

func mustGetEnv(key string, t *testing.T) string {
	val := os.Getenv(key)
	require.NotEmpty(t, val, "No %s env found", key)
	return val
}

func connectToScanner(t *testing.T) *grpc.ClientConn {
	gRPCEndpoint := stringutils.OrDefault(os.Getenv(scannerGRPCEndpointEnv), "localhost:8081")
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := grpc.DialContext(context.Background(), gRPCEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
	require.NoError(t, err)
	return conn
}

func scanImage(client v1.ScanServiceClient, req *v1.ScanImageRequest, t *testing.T) *v1.ScanImageResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scanImageResp, err := client.ScanImage(ctx, req)
	require.NoError(t, err)
	require.Equal(t, scanImageResp.GetStatus(), v1.ScanStatus_SUCCEEDED)
	return scanImageResp
}

func scanPublicDockerHubImage(client v1.ScanServiceClient, imageName string, t *testing.T) *v1.ScanImageResponse {
	return scanImage(client, &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.ScanImageRequest_RegistryData{
			Url: "https://registry-1.docker.io",
		},
	}, t)
}

func scanDockerIOStackRoxImage(client v1.ScanServiceClient, imageName string, t *testing.T) *v1.ScanImageResponse {
	user, pass := mustGetDockerCredentials(t)
	return scanImage(client, &v1.ScanImageRequest{
		Image: imageName,
		Registry: &v1.ScanImageRequest_RegistryData{
			Url:      "https://registry-1.docker.io",
			Username: user,
			Password: pass,
		},
	}, t)
}
