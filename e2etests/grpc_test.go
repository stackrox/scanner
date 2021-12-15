// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/imagescan"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	namespaces "github.com/stackrox/scanner/pkg/wellknownnamespaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCScanImage(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)
	scanImageResp := scanPublicDockerHubImage(client, "nginx", false, t)

	getScanResp, err := client.GetImageScan(context.Background(), &v1.GetImageScanRequest{
		ImageSpec: &v1.ImageSpec{Image: scanImageResp.Image.GetImage()},
	})
	require.NoError(t, err)
	assert.NotZero(t, len(getScanResp.GetImage().GetFeatures()))
}

func verifyImage(t *testing.T, imgScan *v1.Image, test testCase) {
	// Filter out vulnerabilities with no metadata
	for _, feature := range imgScan.Features {
		filteredVulns := feature.Vulnerabilities[:0]
		for _, vuln := range feature.Vulnerabilities {
			if vuln.MetadataV2 != nil {
				filteredVulns = append(filteredVulns, vuln)
			}
		}
		feature.Vulnerabilities = filteredVulns
	}

	for _, feature := range imagescan.ConvertFeatures(test.expectedFeatures) {
		t.Run(fmt.Sprintf("%s/%s/%s", test.image, feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingGRPCFeature(t, imgScan.Features, feature, false)
			if matching.Vulnerabilities != nil {
				sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
					return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
				})
			}

			if test.checkProvidedExecutables {
				assert.ElementsMatch(t, feature.ProvidedExecutables, matching.ProvidedExecutables)
			}
			feature.ProvidedExecutables = nil
			matching.ProvidedExecutables = nil

			if !test.onlyCheckSpecifiedVulns {
				if len(matching.Vulnerabilities) != len(feature.Vulnerabilities) {
					fmt.Printf("Matching: %s\n", matching.Vulnerabilities)
					fmt.Printf("Expected Feature: %s\n", feature.Vulnerabilities)
				}

				require.Equal(t, len(feature.Vulnerabilities), len(matching.Vulnerabilities))
				for i, matchingVuln := range matching.Vulnerabilities {
					expectedVuln := feature.Vulnerabilities[i]
					checkGRPCMatch(t, expectedVuln, matchingVuln)
				}
			} else {
				for _, expectedVuln := range feature.Vulnerabilities {
					var foundMatch bool
					for _, matchingVuln := range matching.Vulnerabilities {
						if expectedVuln.Name != matchingVuln.Name {
							continue
						}
						foundMatch = true
						checkGRPCMatch(t, expectedVuln, matchingVuln)
					}
					assert.True(t, foundMatch)
				}
			}
			feature.Vulnerabilities = nil
			matching.Vulnerabilities = nil

			// Ensure the parts of the feature aside from the provided executables and vulnerabilities are equal, too.
			assert.Equal(t, *feature, *matching)
		})
	}

	for _, feature := range imagescan.ConvertFeatures(test.unexpectedFeatures) {
		assert.Nil(t, getMatchingGRPCFeature(t, imgScan.Features, feature, true))
	}
}

func getMatchingGRPCFeature(t *testing.T, features []*v1.Feature, featureToFind *v1.Feature, allowNotFound bool) *v1.Feature {
	candidateIdx := -1
	for i, f := range features {
		if f.Name == featureToFind.Name && f.Version == featureToFind.Version {
			require.Equal(t, -1, candidateIdx, "Found multiple features for %s/%s", f.Name, f.Version)
			candidateIdx = i
		}
	}
	if allowNotFound && candidateIdx == -1 {
		return nil
	}
	require.NotEqual(t, -1, candidateIdx, "Feature %+v not in list: %v", featureToFind, features)
	return features[candidateIdx]
}

func checkGRPCMatch(t *testing.T, expectedVuln, matchingVuln *v1.Vulnerability) {
	if expectedVuln.MetadataV2 == nil {
		assert.Nil(t, matchingVuln.MetadataV2, "Expected no metadata for %s but got some", expectedVuln.Name)
	} else {
		metadata := expectedVuln.MetadataV2
		// Ignore modified time and published time
		metadata.LastModifiedDateTime = ""
		metadata.PublishedDateTime = ""

		matchingMetadata := matchingVuln.MetadataV2
		// Ignore modified time and published time
		matchingMetadata.LastModifiedDateTime = ""
		matchingMetadata.PublishedDateTime = ""

		assert.Equal(t, metadata, matchingMetadata)
	}
	expectedVuln.MetadataV2 = nil
	matchingVuln.MetadataV2 = nil
	assert.Equal(t, expectedVuln, matchingVuln)
}

func isUncertifiedRHEL(notes []v1.Note) bool {
	for _, note := range notes {
		if note == v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE {
			return true
		}
	}

	return false
}

func TestGRPCGetImageComponents(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)

	_, inCIRun := os.LookupEnv("CI")

	for _, testCase := range testCases {
		if inCIRun && strings.HasPrefix(testCase.image, "docker.io/stackrox/sandbox") {
			testCase.image = strings.Replace(testCase.image, "docker.io/stackrox/sandbox:", "quay.io/rhacs-eng/qa:sandbox-", -1)
			testCase.registry = "https://quay.io"
			testCase.username = os.Getenv("QUAY_RHACS_ENG_RO_USERNAME")
			testCase.password = os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD")
		}

		imgComponentsResp, err := client.GetImageComponents(context.Background(), &v1.GetImageComponentsRequest{
			Image: testCase.image,
			Registry: &v1.RegistryData{
				Url:      testCase.registry,
				Username: testCase.username,
				Password: testCase.password,
				Insecure: true,
			},
		})
		require.Nil(t, err)

		assert.Equal(t, imgComponentsResp.GetStatus(), v1.ScanStatus_SUCCEEDED, "Image %s", testCase.image)
		assert.Equal(t, testCase.uncertifiedRHEL, isUncertifiedRHEL(imgComponentsResp.Notes), "Image %s", testCase.image)
		verifyComponents(t, imgComponentsResp.GetComponents(), testCase)
	}
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

/*
func TestGRPCVulnDefsMetadata(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewVulnDefsServiceClient(conn)
	metadata, err := client.GetVulnDefsMetadata(context.Background(), &v1.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, metadata.GetLastUpdatedTime())
}
*/
