package e2etests

import (
	"context"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFeatureMultipleImages(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanPublicDockerHubImage(client, "alpine:3.10.0@sha256:6e8a04da457c3a62a2e3d4ecff45c990dd741e1192e97aa86fc734d2c348ed20", t)
	_, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)

	// This version of alpine shares some features with the previous version. Make sure this does not error.
	scanResp = scanPublicDockerHubImage(client, "alpine:3.10.1@sha256:ef77e1079a17df210045ffa5dc19214ccdb89e001f32ffab2e61a1c743c2aec7", t)
	_, err = client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)
}
