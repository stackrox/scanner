package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestScanImage(t *testing.T) {
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
		Image: scanImageResp.Image.GetImage(),
	})
	fmt.Printf("%+v %+v\n", getScanResp, err)
}
