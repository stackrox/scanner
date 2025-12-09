//go:build e2e
// +build e2e

// This file has tests which are only used to test the full-Scanner (ie not Scanner-slim).

package e2etests

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/stackrox/scanner/api/v1/features"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
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
	assert.Equal(t, test.namespace, imgScan.GetNamespace())

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

	for _, feature := range features.ConvertFeatures(test.expectedFeatures) {
		t.Run(fmt.Sprintf("%s/%s/%s", test.image, feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingGRPCFeature(t, imgScan.Features, feature, false)
			if matching.Vulnerabilities != nil {
				sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
					return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
				})
			}

			if test.checkProvidedExecutables {
				for _, exec := range matching.ProvidedExecutables {
					sort.Slice(exec.RequiredFeatures, func(i, j int) bool {
						return exec.RequiredFeatures[i].GetName() < exec.RequiredFeatures[j].GetName() ||
							exec.RequiredFeatures[i].GetName() == exec.RequiredFeatures[j].GetName() && exec.RequiredFeatures[i].GetVersion() < exec.RequiredFeatures[j].GetVersion()
					})
				}

				for _, exec := range feature.ProvidedExecutables {
					sort.Slice(exec.RequiredFeatures, func(i, j int) bool {
						return exec.RequiredFeatures[i].GetName() < exec.RequiredFeatures[j].GetName() ||
							exec.RequiredFeatures[i].GetName() == exec.RequiredFeatures[j].GetName() && exec.RequiredFeatures[i].GetVersion() < exec.RequiredFeatures[j].GetVersion()
					})
				}
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
					assert.Truef(t, foundMatch, "Expected to find %s in scan results\nFound the following: %s", expectedVuln.Name, matching.Vulnerabilities)
				}
			}
			feature.Vulnerabilities = nil
			matching.Vulnerabilities = nil

			// Clear FixedBy as it changes frequently when new advisories are published.
			// The per-vulnerability FixedBy is still checked above via checkGRPCMatch().
			feature.FixedBy = ""
			matching.FixedBy = ""

			// Ensure the parts of the feature aside from the provided executables and vulnerabilities are equal, too.
			assert.Equal(t, *feature, *matching)
		})
	}

	for _, feature := range features.ConvertFeatures(test.unexpectedFeatures) {
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
	if candidateIdx == -1 {
		featureToFind.Vulnerabilities = nil
		for _, feature := range features {
			feature.Vulnerabilities = nil
		}
		fmt.Printf("Feature %+v not in list: %v", featureToFind, features)
	}
	require.NotEqual(t, -1, candidateIdx)
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

func TestGRPCGetImageVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)

	for _, testCase := range testCases {
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

		// This test assumes TestGRPCGetImageComponents passes, so there is no need to check the component response.

		vulnsResp, err := client.GetImageVulnerabilities(context.Background(), &v1.GetImageVulnerabilitiesRequest{
			Image:      testCase.image,
			Components: imgComponentsResp.GetComponents(),
			Notes:      imgComponentsResp.GetNotes(),
		})
		require.NoError(t, err)
		verifyImage(t, vulnsResp.GetImage(), testCase)
	}
}

func TestGRPCVulnDefsMetadata(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewVulnDefsServiceClient(conn)
	metadata, err := client.GetVulnDefsMetadata(context.Background(), &v1.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, metadata.GetLastUpdatedTime())
}
