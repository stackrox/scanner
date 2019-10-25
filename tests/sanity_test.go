package tests

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/davecgh/go-spew/spew"
	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getMatchingFeature(featureList []v1.Feature, featureToFind v1.Feature, t *testing.T) v1.Feature {
	candidateIdx := -1
	for i, f := range featureList {
		if f.Name == featureToFind.Name && f.Version == featureToFind.Version {
			require.Equal(t, -1, candidateIdx, "Found multiple features for %s/%s", f.Name, f.Version)
			candidateIdx = i
		}
	}
	require.NotEqual(t, -1, candidateIdx, "Feature %+v not in list", featureToFind)
	return featureList[candidateIdx]
}

func testImage(client *client.Clairify, imageRequest *types.ImageRequest, expectedFeatures []v1.Feature, t *testing.T) {
	img, err := client.AddImage("", "", imageRequest)
	require.NoError(t, err)

	env, err := client.RetrieveImageDataBySHA(img.SHA, true, true)
	require.NoError(t, err)
	require.Nil(t, env.Error)

	// Useful when writing things out at first.
	if len(expectedFeatures) == 0 {
		t.Fatal(spew.Sdump(env.Layer.Features))
	}

	for _, feature := range expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingFeature(env.Layer.Features, feature, t)
			sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
				return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
			})
			require.Equal(t, len(matching.Vulnerabilities), len(feature.Vulnerabilities))
			for i, matchingVuln := range matching.Vulnerabilities {
				expectedVuln := feature.Vulnerabilities[i]
				if expectedVuln.Metadata == nil {
					assert.Nil(t, matchingVuln.Metadata, "Expected no metadata for %s but got some", expectedVuln.Name)
				} else {
					for _, keys := range [][]string{
						{"NVD", "CVSSv2", "ExploitabilityScore"},
						{"NVD", "CVSSv2", "Score"},
						{"NVD", "CVSSv2", "ImpactScore"},
						{"NVD", "CVSSv2", "Vectors"},
						{"NVD", "CVSSv3", "ExploitabilityScore"},
						{"NVD", "CVSSv3", "Score"},
						{"NVD", "CVSSv3", "ImpactScore"},
						{"NVD", "CVSSv3", "Vectors"},
					} {
						assert.NotNil(t, deepGet(expectedVuln.Metadata, keys...), "Value for nil for %+v", keys)
						assert.Equal(t, deepGet(expectedVuln.Metadata, keys...), deepGet(matchingVuln.Metadata, keys...), "Failed for %+v", keys)
					}
				}
				expectedVuln.Metadata = nil
				matchingVuln.Metadata = nil
				assert.Equal(t, expectedVuln, matchingVuln)
			}
			matching.Vulnerabilities = nil
			feature.Vulnerabilities = nil
			assert.Equal(t, matching, feature)
		})
	}
}

func TestImageSanity(t *testing.T) {
	endpoint := os.Getenv("SCANNER_ENDPOINT")
	require.NotEmpty(t, endpoint, "no scanner endpoint specified")

	cli := client.New(endpoint, true)

	for _, testCase := range []struct {
		image            string
		registry         string
		expectedFeatures []v1.Feature
	}{
		{
			image:    "docker.io/library/nginx:1.10",
			registry: "https://registry-1.docker.io",
			expectedFeatures: []v1.Feature{
				{
					Name:            "diffutils",
					NamespaceName:   "debian:8",
					VersionFormat:   "dpkg",
					Version:         "1:3.3-1",
					Vulnerabilities: nil,
					AddedBy:         "sha256:6d827a3ef358f4fa21ef8251f95492e667da826653fd43641cef5a877dc03a70",
				},
				{
					Name:          "coreutils",
					NamespaceName: "debian:8",
					VersionFormat: "dpkg",
					Version:       "8.23-4",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:          "CVE-2016-2781",
							NamespaceName: "debian:8",
							Description:   "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2016-2781",
							Severity:      "Low",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         2.9,
										"PublishedDateTime":   "2017-02-07T15:59Z",
										"Score":               2.1,
										"Vectors":             "AV:L/AC:L/Au:N/C:N/I:P/A:N",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.0,
										"ImpactScore":         4.0,
										"Score":               6.5,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
									},
								},
							},
						},
						{
							Name:          "CVE-2017-18018",
							NamespaceName: "debian:8",
							Description:   "In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX \"-R -L\" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2017-18018",
							Severity:      "Negligible",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 3.4,
										"ImpactScore":         2.9,
										"Score":               1.9,
										"Vectors":             "AV:L/AC:M/Au:N/C:N/I:P/A:N",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.0,
										"ImpactScore":         3.6,
										"Score":               4.7,
										"Vectors":             "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
									},
									"PublishedDateTime":    "2018-01-04T04:29Z",
									"LastModifiedDateTime": "2018-01-19T15:46Z",
								},
							},
						},
					},
					AddedBy: "sha256:6d827a3ef358f4fa21ef8251f95492e667da826653fd43641cef5a877dc03a70",
				},
			},
		},
		{
			image:    "docker.io/kaizheh/apache-struts2-cve-2017-5638:latest",
			registry: "https://registry-1.docker.io",
			expectedFeatures: []v1.Feature{
				{
					Name:          "apt",
					NamespaceName: "debian:8",
					VersionFormat: "dpkg",
					Version:       "1.0.9.8.4",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:          "CVE-2011-3374",
							NamespaceName: "debian:8",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2011-3374",
							Severity:      "Negligible",
						},
						{
							Name:          "CVE-2019-3462",
							NamespaceName: "debian:8",
							Description:   "Incorrect sanitation of the 302 redirect field in HTTP transport method of apt versions 1.4.8 and earlier can lead to content injection by a MITM attacker, potentially leading to remote code execution on the target machine.",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2019-3462",
							Severity:      "High",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ImpactScore":         float64(10),
										"PublishedDateTime":   "2019-01-28T21:29Z",
										"Score":               9.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:C/I:C/A:C",
										"ExploitabilityScore": 8.6,
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
							},

							FixedBy: "1.0.9.8.5",
						},
					},
					AddedBy: "sha256:9f0706ba7422412cd468804fee456786f88bed94bf9aea6dde2a47f770d19d27",
				},
			},
		},
	} {
		t.Run(testCase.image, func(t *testing.T) {
			testImage(cli, &types.ImageRequest{Image: testCase.image, Registry: testCase.registry}, testCase.expectedFeatures, t)
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
