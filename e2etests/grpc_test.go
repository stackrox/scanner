// +build e2e

package e2etests

import (
	"context"
	"testing"

	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCScanImage(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)
	scanImageResp := scanPublicDockerHubImage(client, "nginx", t)

	getScanResp, err := client.GetImageScan(context.Background(), &v1.GetImageScanRequest{
		ImageSpec: &v1.ImageSpec{Image: scanImageResp.Image.GetImage()},
	})
	require.NoError(t, err)
	assert.NotZero(t, len(getScanResp.GetImage().GetFeatures()))
}

func TestGRPCVulnDefsMetadata(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewVulnDefsServiceClient(conn)
	metadata, err := client.GetVulnDefsMetadata(context.Background(), &v1.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, metadata.GetLastUpdatedTime())
}
