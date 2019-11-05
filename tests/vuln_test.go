package tests

import (
	"context"
	"fmt"
	"testing"

	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulns(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanDockerIOStackRoxImage(client, "docker.io/stackrox/vuln-images:django-cve-2019-14235", t)
	scan, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)

	// If the test failed, print helpful debug information.
	defer func() {
		if t.Failed() {
			for _, feat := range scan.GetImage().GetFeatures() {
				fmt.Println(feat.GetName(), feat.GetVersion())
			}
			fmt.Println("DONE PRINTING COMPONENTS FROM SCAN")

			componentsMap, err := client.GetLanguageLevelComponents(context.Background(), &v1.GetLanguageLevelComponentsRequest{
				ImageSpec: scanResp.GetImage(),
			})
			require.NoError(t, err)
			for _, components := range componentsMap.GetLayerToComponents() {
				for _, component := range components.GetComponents() {
					fmt.Println(component.GetName(), component.GetVersion())
				}
			}
			fmt.Println("DONE PRINTING LANGUAGE LEVEL COMPONENTS")
		}
	}()
	expectedFeatures := []struct {
		name          string
		version       string
		expectedVulns []string
	}{
		{"django", "2.1", []string{"CVE-2019-14235"}},
	}

	for _, expectedFeat := range expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", expectedFeat.name, expectedFeat.version), func(t *testing.T) {
			var matching *v1.Feature
			for _, actualFeature := range scan.GetImage().GetFeatures() {
				if actualFeature.GetName() == expectedFeat.name && actualFeature.GetVersion() == expectedFeat.version {
					matching = actualFeature
					break
				}
			}
			assert.NotNil(t, matching)
			for _, expectedVuln := range expectedFeat.expectedVulns {
				var found bool
				for _, actualVuln := range matching.GetVulnerabilities() {
					if actualVuln.GetName() == expectedVuln {
						found = true
						break
					}
				}
				assert.True(t, found, "Vuln %s not found", expectedVuln)
			}
		})
	}
}
