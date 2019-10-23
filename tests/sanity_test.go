package tests

import (
	"fmt"
	"os"
	"sort"
	"testing"

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

func TestImageSanity(t *testing.T) {
	endpoint := os.Getenv("SCANNER_ENDPOINT")
	require.NotEmpty(t, endpoint, "no scanner endpoint specified")

	cli := client.New(endpoint, true)

	img, err := cli.AddImage("", "", &types.ImageRequest{
		Image:    "nginx:1.10",
		Registry: "https://registry-1.docker.io",
		Insecure: false,
	})
	require.NoError(t, err)

	env, err := cli.RetrieveImageDataBySHA(img.SHA, true, true)
	require.NoError(t, err)
	require.Nil(t, env.Error)

	expectedFeatures := []v1.Feature{
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
	}

	for _, feature := range expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", feature.Name, feature.Version), func(t *testing.T) {
			matching := getMatchingFeature(env.Layer.Features, feature, t)
			sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
				return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
			})
			require.Equal(t, len(matching.Vulnerabilities), len(feature.Vulnerabilities))
			for i, matchingVuln := range matching.Vulnerabilities {
				assert.Equal(t, feature.Vulnerabilities[i], matchingVuln, "Failed for vuln %s", matchingVuln.Name)
			}
			assert.Equal(t, matching, feature)
		})
	}
}
