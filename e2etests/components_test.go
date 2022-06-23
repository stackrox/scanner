//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/jsonpb"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
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
	client := v1.NewImageScanServiceClient(conn)
	scanResp := scanPublicDockerHubImage(client, "docker.io/anchore/anchore-engine:v0.5.0", true, t)
	getComponentsResp, err := client.GetLanguageLevelComponents(context.Background(), &v1.GetLanguageLevelComponentsRequest{
		ImageSpec: &v1.ImageSpec{
			Digest: scanResp.GetImage().GetDigest(),
		},
		UncertifiedRHEL: true,
	})
	assert.NoError(t, err)

	gotComponents := getComponentsResp.GetLayerToComponents()

	assert.Equal(t, len(anchoreComponents), len(gotComponents), "Didn't get the same number of layers: %s %s", spew.Sdump(anchoreComponents), spew.Sdump(gotComponents))

	for layer, components := range anchoreComponents {
		got, ok := gotComponents[layer]
		assert.True(t, ok, "Layer %q not in got components", layer)
		assert.ElementsMatch(t, components.GetComponents(), got.GetComponents())
	}
}

func TestRemovedComponents(t *testing.T) {
	cases := []struct {
		distro            string
		missingComponents []string
	}{
		{
			distro: "debian",
			missingComponents: []string{
				"apt",
				"curl",
			},
		},
		{
			distro: "ubuntu",
			missingComponents: []string{
				"apt",
				"curl",
			},
		},
		{
			distro: "alpine",
			missingComponents: []string{
				"apk",
				"curl",
			},
		},
		{
			distro: "centos",
			missingComponents: []string{
				"rpm",
				"yum",
				"curl",
			},
		},
		{
			distro: "rhel",
			missingComponents: []string{
				"rpm",
				"yum",
				"curl",
			},
		},
	}
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)
	_, inCIRun := os.LookupEnv("CI")
	for _, c := range cases {
		t.Run(c.distro, func(t *testing.T) {
			scanResp := scanQuayStackRoxImage(client, fmt.Sprintf("quay.io/rhacs-eng/qa:%s-package-removal", c.distro), true, t)
			scan, err := client.GetImageScan(context.Background(), &v1.GetImageScanRequest{
				ImageSpec:       scanResp.GetImage(),
				UncertifiedRHEL: true,
			})
			require.NoError(t, err)

			for _, f := range scan.GetImage().GetFeatures() {
				for _, missing := range c.missingComponents {
					assert.NotEqual(t, missing, f.GetName(), "Incorrectly found %s in %s image", f.GetName(), c.distro)
				}
			}
		})
	}
}
