// +build e2e

package e2etests

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getMatchingFeature(t *testing.T, featureList []v1.Feature, featureToFind v1.Feature, allowNotFound bool) *v1.Feature {
	candidateIdx := -1
	for i, f := range featureList {
		if f.Name == featureToFind.Name && f.Version == featureToFind.Version {
			require.Equal(t, -1, candidateIdx, "Found multiple features for %s/%s", f.Name, f.Version)
			candidateIdx = i
		}
	}
	if allowNotFound && candidateIdx == -1 {
		return nil
	}
	if candidateIdx == -1 {
		// TODO: delete
		fmt.Printf("Feature %+v not in list: %v", featureToFind, featureList)
	}
	require.NotEqual(t, -1, candidateIdx, "Feature %+v not in list: %v", featureToFind, featureList)
	return &featureList[candidateIdx]
}

func checkMatch(t *testing.T, source string, expectedVuln, matchingVuln v1.Vulnerability) {
	if expectedVuln.Metadata == nil {
		assert.Nil(t, matchingVuln.Metadata, "Expected no metadata for %s but got some", expectedVuln.Name)
	} else {
		for _, keys := range [][]string{
			{source, "CVSSv2", "ExploitabilityScore"},
			{source, "CVSSv2", "Score"},
			{source, "CVSSv2", "ImpactScore"},
			{source, "CVSSv2", "Vectors"},
			{source, "CVSSv3", "ExploitabilityScore"},
			{source, "CVSSv3", "Score"},
			{source, "CVSSv3", "ImpactScore"},
			{source, "CVSSv3", "Vectors"},
		} {
			assert.NotNil(t, deepGet(expectedVuln.Metadata, keys...), "Value for nil for %+v", keys)
			assert.Equal(t, deepGet(expectedVuln.Metadata, keys...), deepGet(matchingVuln.Metadata, keys...), "Failed for %+v", keys)
		}
	}
	expectedVuln.Metadata = nil
	matchingVuln.Metadata = nil
	assert.Equal(t, expectedVuln, matchingVuln)
}

func verifyImageHasExpectedFeatures(t *testing.T, client *client.Clairify, username, password, source string, imageRequest *types.ImageRequest, onlyCheckSpecifiedVulns, checkProvidedExecutables bool, expectedFeatures, unexpectedFeatures []v1.Feature) {
	img, err := client.AddImage(username, password, imageRequest)
	require.NoError(t, err)

	env, err := client.RetrieveImageDataBySHA(img.SHA, &types.GetImageDataOpts{
		UncertifiedRHELResults: imageRequest.UncertifiedRHELScan,
	})
	require.NoError(t, err)
	require.Nil(t, env.Error)

	// Filter out vulnerabilities with no metadata
	for idx, feature := range env.Layer.Features {
		filteredVulns := feature.Vulnerabilities[:0]
		for _, vuln := range feature.Vulnerabilities {
			if vuln.Metadata != nil {
				filteredVulns = append(filteredVulns, vuln)
			}
		}
		// env.Layer.Features is a []Feature so cannot just assign to feature
		env.Layer.Features[idx].Vulnerabilities = filteredVulns
	}

	for _, feature := range expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingFeature(t, env.Layer.Features, feature, false)
			if matching.Vulnerabilities != nil {
				sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
					return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
				})
			}

			if checkProvidedExecutables {
				assert.ElementsMatch(t, feature.ProvidedExecutables, matching.ProvidedExecutables)
			}
			feature.ProvidedExecutables = nil
			matching.ProvidedExecutables = nil

			if !onlyCheckSpecifiedVulns {
				if len(matching.Vulnerabilities) != len(feature.Vulnerabilities) {
					matchingBytes, _ := json.MarshalIndent(matching.Vulnerabilities, "", "  ")
					featureVulnsBytes, _ := json.MarshalIndent(feature.Vulnerabilities, "", "  ")
					fmt.Printf("Matching: %s\n", matchingBytes)
					fmt.Printf("Expected Feature: %s\n", featureVulnsBytes)
				}

				require.Equal(t, len(feature.Vulnerabilities), len(matching.Vulnerabilities))
				for i, matchingVuln := range matching.Vulnerabilities {
					expectedVuln := feature.Vulnerabilities[i]
					checkMatch(t, source, expectedVuln, matchingVuln)
				}
			} else {
				for _, expectedVuln := range feature.Vulnerabilities {
					var foundMatch bool
					for _, matchingVuln := range matching.Vulnerabilities {
						if expectedVuln.Name != matchingVuln.Name {
							continue
						}
						foundMatch = true
						checkMatch(t, source, expectedVuln, matchingVuln)
					}
					assert.True(t, foundMatch)
				}
			}
			feature.Vulnerabilities = nil
			matching.Vulnerabilities = nil

			// Ensure the parts of the feature aside from the provided executables and vulnerabilities are equal, too.
			assert.Equal(t, feature, *matching)
		})
	}

	for _, feature := range unexpectedFeatures {
		assert.Nil(t, getMatchingFeature(t, env.Layer.Features, feature, true))
	}
}

func TestImageSanity(t *testing.T) {
	cli := client.New(getScannerHTTPEndpoint(), true)

	_, inCIRun := os.LookupEnv("CI")

	for _, testCase := range testCases {
		t.Run(testCase.image, func(t *testing.T) {
			if inCIRun && strings.HasPrefix(testCase.image, "docker.io/stackrox/sandbox") {
				testCase.image = strings.Replace(testCase.image, "docker.io/stackrox/sandbox:", "quay.io/rhacs-eng/qa:sandbox-", -1)
				testCase.registry = "https://quay.io"
				testCase.username = os.Getenv("QUAY_RHACS_ENG_RO_USERNAME")
				testCase.password = os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD")
			}
			verifyImageHasExpectedFeatures(t, cli, testCase.username, testCase.password, testCase.source, &types.ImageRequest{Image: testCase.image, Registry: testCase.registry, UncertifiedRHELScan: testCase.uncertifiedRHEL}, testCase.onlyCheckSpecifiedVulns, testCase.checkProvidedExecutables, testCase.expectedFeatures, testCase.unexpectedFeatures)
		})
	}
}

func deepGet(m map[string]interface{}, keys ...string) interface{} {
	var currVal interface{} = m
	for _, k := range keys {
		if currVal == nil {
			return nil
		}
		asMap := currVal.(map[string]interface{})
		if asMap == nil {
			return nil
		}
		currVal = asMap[k]
	}
	return currVal
}
