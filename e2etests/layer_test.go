// +build e2e

package e2etests

import (
	"context"
	"testing"

	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLayersAndLocations(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanPublicDockerHubImage(client, "docker.io/syndesis/syndesis-s2i:latest@sha256:9c3ea4777a61896364445fb13000e84da0d4596f478ff0520d3140a69758b6f2", t)
	scan, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)

	// Make sure that all java packages have a location
	for _, f := range scan.GetImage().GetFeatures() {
		if f.FeatureType != "rpm" {
			assert.NotEmpty(t, f.GetLocation())
		}
	}
	// sha256:2a28f35f97b8a65f89f83a39efa0b3926a2f5e442c71ae99c549af29d535e54c is a layer that chowns the files
	for _, f := range scan.GetImage().GetFeatures() {
		assert.NotEqual(t, "sha256:2a28f35f97b8a65f89f83a39efa0b3926a2f5e442c71ae99c549af29d535e54c", f.GetAddedByLayer())
	}
}
