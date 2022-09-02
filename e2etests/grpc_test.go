//go:build e2e || slim_e2e
// +build e2e slim_e2e

package e2etests

import (
	"context"
	"sort"
	"testing"

	apiV1 "github.com/stackrox/scanner/api/v1"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	namespaces "github.com/stackrox/scanner/pkg/wellknownnamespaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCGetImageComponents(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)

	for _, testCase := range getEnabledTestCases() {
		// Only run test cases for selected features if they are enabled.
		if !testCase.requiredFeatureFlag.Enabled() {
			continue
		}
		t.Run(testCase.image, func(t *testing.T) {
			imgComponentsResp, err := client.GetImageComponents(context.Background(), &v1.GetImageComponentsRequest{
				Image: testCase.image,
				Registry: &v1.RegistryData{
					Url:      testCase.registry,
					Username: testCase.username,
					Password: testCase.password,
					Insecure: true,
				},
			})
			require.NoError(t, err)
			require.NotNil(t, imgComponentsResp.GetStatus())

			assert.Equal(t, imgComponentsResp.GetStatus(), v1.ScanStatus_SUCCEEDED, "Image %s", testCase.image)
			assert.Equal(t, testCase.uncertifiedRHEL, hasUncertifiedRHEL(imgComponentsResp.GetNotes()), "Image %s", testCase.image)
			assert.Equal(t, testCase.namespace, imgComponentsResp.GetComponents().GetNamespace())
			verifyComponents(t, imgComponentsResp.GetComponents(), testCase)
		})
	}
}

func hasUncertifiedRHEL(notes []v1.Note) bool {
	for _, note := range notes {
		if note == v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE {
			return true
		}
	}

	return false
}

func verifyComponents(t *testing.T, components *v1.Components, test testCase) {
	assert.True(t, len(components.RhelComponents) == 0 || len(components.OsComponents) == 0)

	// Skip language components at this time.
	var nonLanguageFeatures []apiV1.Feature
	for _, feature := range test.expectedFeatures {
		if feature.Location == "" {
			feature.Vulnerabilities = nil
			feature.FixedBy = ""
			if !namespaces.IsRHELNamespace(feature.NamespaceName) {
				feature.VersionFormat = ""
			}
			nonLanguageFeatures = append(nonLanguageFeatures, feature)
		}
	}

	features := make([]apiV1.Feature, 0, len(nonLanguageFeatures))
	for _, c := range components.OsComponents {
		features = append(features, apiV1.Feature{
			Name:          c.Name,
			NamespaceName: c.Namespace,
			Version:       c.Version,
			AddedBy:       c.AddedBy,
			Executables:   c.Executables,
		})
	}
	for _, c := range components.RhelComponents {
		features = append(features, apiV1.Feature{
			Name:          c.Name,
			NamespaceName: c.Namespace,
			VersionFormat: "rpm",
			Version:       c.Version + "." + c.Arch,
			AddedBy:       c.AddedBy,
			Executables:   c.Executables,
		})
	}

	for _, expectedFeature := range nonLanguageFeatures {
		f := getMatchingFeature(t, features, expectedFeature, false)

		if test.checkProvidedExecutables {
			for _, exec := range f.Executables {
				sort.Slice(exec.RequiredFeatures, func(i, j int) bool {
					return exec.RequiredFeatures[i].GetName() < exec.RequiredFeatures[j].GetName() ||
						exec.RequiredFeatures[i].GetName() == exec.RequiredFeatures[j].GetName() && exec.RequiredFeatures[i].GetVersion() < exec.RequiredFeatures[j].GetVersion()
				})
			}
			assert.ElementsMatch(t, expectedFeature.Executables, f.Executables)
		}
		expectedFeature.Executables = nil
		f.Executables = nil

		assert.Equal(t, expectedFeature, *f)
	}
}
