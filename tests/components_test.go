package tests

import (
	"context"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/jsonpb"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadExpectedComponentResponse(filePath string, t *testing.T) map[string]*v1.LanguageLevelComponents {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	var resp v1.GetLanguageLevelComponentsResponse
	require.NoError(t, jsonpb.Unmarshal(f, &resp))
	return resp.GetLayerToComponents()
}

func TestPythonComponents(t *testing.T) {
	anchoreComponents := loadExpectedComponentResponse("./testdata/anchore_components.json", t)
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanPublicDockerHubImage(client, "docker.io/anchore/anchore-engine:v0.5.0", t)
	getComponentsResp, err := client.GetLanguageLevelComponents(context.Background(), &v1.GetLanguageLevelComponentsRequest{
		ImageSpec: &v1.ImageSpec{
			Digest: scanResp.GetImage().GetDigest(),
		},
	})
	gotComponents := getComponentsResp.GetLayerToComponents()
	assert.NoError(t, err)

	assert.Equal(t, len(anchoreComponents), len(gotComponents), "Didn't get the same number of layers: %s %s", spew.Sdump(anchoreComponents), spew.Sdump(gotComponents))

	for layer, components := range anchoreComponents {
		got, ok := gotComponents[layer]
		assert.True(t, ok, "Layer %q not in got components", layer)
		assert.ElementsMatch(t, components.GetComponents(), got.GetComponents())
	}
}
