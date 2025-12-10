//go:build e2e
// +build e2e

package e2etests

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkMatch(t *testing.T, source string, expectedVuln, matchingVuln v1.Vulnerability) {
	if expectedVuln.Metadata == nil {
		assert.Nil(t, matchingVuln.Metadata, "Expected no metadata for %s but got some", expectedVuln.Name)
	} else {
		keySets := [][]string{
			{source, "CVSSv2", "ExploitabilityScore"},
			{source, "CVSSv2", "Score"},
			{source, "CVSSv2", "ImpactScore"},
			{source, "CVSSv2", "Vectors"},
		}

		testHasCVSSv3 := deepGet(expectedVuln.Metadata, []string{source, "CVSSv3"}...) != nil

		vulnCVSSv3 := deepGet(matchingVuln.Metadata, []string{source, "CVSSv3"}...)
		vulnCVSSv3Vectors := deepGet(matchingVuln.Metadata, []string{source, "CVSSv3", "Vectors"}...)
		// Assume that CVSSv3 scores exist if Vectors is not empty.
		vulnHasCVSSv3 := vulnCVSSv3Vectors != nil && vulnCVSSv3Vectors.(string) != ""

		// If the test case does not have CVSSv3 scores but the matching vuln does, fail the test.
		// This was added when NVD stopped returning CVSSv3 data for some vulns which we had
		// test cases for, this condition ensures we are alerted when/if the data returns.
		assert.False(t, !testHasCVSSv3 && vulnHasCVSSv3, "Test case for %q is missing CVSSv3 scores, please add the scores to the test case. Scores from vuln data: %+v", expectedVuln.Name, vulnCVSSv3)

		// Compare CVSSv3 data only when it exists in the test case.
		if testHasCVSSv3 {
			keySets = append(keySets, [][]string{
				{source, "CVSSv3", "ExploitabilityScore"},
				{source, "CVSSv3", "Score"},
				{source, "CVSSv3", "ImpactScore"},
				{source, "CVSSv3", "Vectors"},
			}...)
		} else {
			t.Logf("WARN: No CVSSv3 data provided for %q, skipping CVSSv3 field validation.", expectedVuln.Name)
		}

		for _, keys := range keySets {
			assert.NotNil(t, deepGet(expectedVuln.Metadata, keys...), "Value for nil for %+v in vuln %q", keys, expectedVuln.Name)
			assert.Equal(t, deepGet(expectedVuln.Metadata, keys...), deepGet(matchingVuln.Metadata, keys...), "Failed for %+v in vuln %q", keys, expectedVuln.Name)
		}
	}
	expectedVuln.Metadata = nil
	matchingVuln.Metadata = nil
	assert.Equal(t, expectedVuln, matchingVuln)
}

func verifyImageHasExpectedFeatures(t *testing.T, client *client.Clairify, test testCase, imageRequest *types.ImageRequest) {
	img, err := client.AddImage(test.username, test.password, imageRequest)
	require.NoError(t, err)

	env, err := client.RetrieveImageDataBySHA(img.SHA, &types.GetImageDataOpts{
		UncertifiedRHELResults: imageRequest.UncertifiedRHELScan,
	})

	require.NoError(t, err)
	require.Nil(t, env.Error)
	require.NotNil(t, env.Layer)

	assert.Equal(t, test.namespace, env.Layer.NamespaceName)

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

	for _, feature := range test.expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingFeature(t, env.Layer.Features, feature, false)
			if matching.Vulnerabilities != nil {
				sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
					return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
				})
			}

			if test.checkProvidedExecutables {
				for _, exec := range matching.Executables {
					sort.Slice(exec.RequiredFeatures, func(i, j int) bool {
						return exec.RequiredFeatures[i].GetName() < exec.RequiredFeatures[j].GetName() ||
							exec.RequiredFeatures[i].GetName() == exec.RequiredFeatures[j].GetName() && exec.RequiredFeatures[i].GetVersion() < exec.RequiredFeatures[j].GetVersion()
					})
				}

				for _, exec := range feature.Executables {
					sort.Slice(exec.RequiredFeatures, func(i, j int) bool {
						return exec.RequiredFeatures[i].GetName() < exec.RequiredFeatures[j].GetName() ||
							exec.RequiredFeatures[i].GetName() == exec.RequiredFeatures[j].GetName() && exec.RequiredFeatures[i].GetVersion() < exec.RequiredFeatures[j].GetVersion()
					})
				}
				assert.ElementsMatch(t, feature.Executables, matching.Executables)
			}
			feature.Executables = nil
			matching.Executables = nil

			matchingBytes, _ := json.MarshalIndent(matching.Vulnerabilities, "", "  ")
			if !test.onlyCheckSpecifiedVulns {
				if len(matching.Vulnerabilities) != len(feature.Vulnerabilities) {
					featureVulnsBytes, _ := json.MarshalIndent(feature.Vulnerabilities, "", "  ")
					fmt.Printf("Matching: %s\n", string(matchingBytes))
					fmt.Printf("Expected Feature: %s\n", string(featureVulnsBytes))
				}

				require.Equal(t, len(feature.Vulnerabilities), len(matching.Vulnerabilities))
				for i, matchingVuln := range matching.Vulnerabilities {
					expectedVuln := feature.Vulnerabilities[i]
					checkMatch(t, test.source, expectedVuln, matchingVuln)
				}
			} else {
				for _, expectedVuln := range feature.Vulnerabilities {
					var foundMatch bool
					for _, matchingVuln := range matching.Vulnerabilities {
						if expectedVuln.Name != matchingVuln.Name {
							continue
						}
						foundMatch = true
						checkMatch(t, test.source, expectedVuln, matchingVuln)
					}
					assert.Truef(t, foundMatch, "Expected to find %s in scan results\nFound the following: %s", expectedVuln.Name, string(matchingBytes))
				}
			}
			feature.Vulnerabilities = nil
			matching.Vulnerabilities = nil

			// Clear FixedBy as it changes frequently when new advisories are published.
			// The per-vulnerability FixedBy is still checked above via checkMatch().
			feature.FixedBy = ""
			matching.FixedBy = ""

			// Ensure the parts of the feature aside from the provided executables and vulnerabilities are equal, too.
			assert.Equal(t, feature, *matching)
		})
	}

	for _, feature := range test.unexpectedFeatures {
		assert.Nil(t, getMatchingFeature(t, env.Layer.Features, feature, true))
	}
}

func TestImageSanity(t *testing.T) {
	cli := client.New(getScannerHTTPEndpoint(), true)

	for _, testCase := range testCases {
		t.Run(testCase.image, func(t *testing.T) {
			verifyImageHasExpectedFeatures(t, cli, testCase, &types.ImageRequest{Image: testCase.image, Registry: testCase.registry, UncertifiedRHELScan: testCase.uncertifiedRHEL})
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
