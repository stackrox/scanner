// +build e2e

package e2etests

import (
	"encoding/json"
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
func verifyImageHasExpectedFeatures(client *client.Clairify, username, password string, imageRequest *types.ImageRequest, expectedFeatures []v1.Feature, t *testing.T) {
	img, err := client.AddImage(username, password, imageRequest)
	require.NoError(t, err)

	env, err := client.RetrieveImageDataBySHA(img.SHA, true, true)
	require.NoError(t, err)
	require.Nil(t, env.Error)

	// Useful when writing things out at first.
	if len(expectedFeatures) == 0 {
		t.Fatal(spew.Sdump(env.Layer.Features))
	}

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
			matching := getMatchingFeature(env.Layer.Features, feature, t)
			if matching.Vulnerabilities != nil {
				sort.Slice(matching.Vulnerabilities, func(i, j int) bool {
					return matching.Vulnerabilities[i].Name < matching.Vulnerabilities[j].Name
				})
			}

			if len(matching.Vulnerabilities) != len(feature.Vulnerabilities) {
				matchingBytes, _ := json.MarshalIndent(matching.Vulnerabilities, "", "  ")
				featureVulnsBytes, _ := json.MarshalIndent(feature.Vulnerabilities, "", "  ")
				fmt.Printf("Matching: %s\n", matchingBytes)
				fmt.Printf("Feature: %s\n", featureVulnsBytes)
			}
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
	cli := client.New(getScannerHTTPEndpoint(t), true)

	for _, testCase := range []struct {
		image              string
		registry           string
		username, password string
		expectedFeatures   []v1.Feature
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
							Description:   "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ImpactScore":         float64(2.9),
										"PublishedDateTime":   "2019-01-28T21:29Z",
										"Score":               4.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:N/I:P/A:N",
										"ExploitabilityScore": 8.6,
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         1.4,
										"Score":               3.7,
										"Vectors":             "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
									},
									"LastModifiedDateTime": "2019-12-04T15:35Z",
									"PublishedDateTime":    "2019-11-26T00:15Z",
								},
							},
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
						{
							Name:          "CVE-2020-3810",
							NamespaceName: "debian:8",
							Description:   "Missing input validation in the ar/tar implementations of APT before version 2.1.2 could result in denial of service when processing specially crafted deb files.",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2020-3810",
							Severity:      "Medium",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         2.9,
										"Score":               4.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.8,
										"ImpactScore":         3.6,
										"Score":               5.5,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2020-05-18T16:36Z",
									"PublishedDateTime":    "2020-05-15T14:15Z",
								},
							},
							FixedBy: "1.0.9.8.6",
						},
					},
					AddedBy: "sha256:9f0706ba7422412cd468804fee456786f88bed94bf9aea6dde2a47f770d19d27",
				},
			},
		},
		{
			image:    "docker.io/anchore/anchore-engine:v0.5.0",
			registry: "https://registry-1.docker.io",
			expectedFeatures: []v1.Feature{
				{
					Name:          "procps-ng",
					NamespaceName: "centos:7",
					VersionFormat: "rpm",
					Version:       "3.3.10-26.el7",
					AddedBy:       "sha256:c8d67acdb2ffaebd638cf55a8fccc63693211060670aa7f0ea1d65b5d2c674dd",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:          "CVE-2018-1121",
							NamespaceName: "centos:7",
							Description:   "DOCUMENTATION: Since the kernel's proc_pid_readdir() returns PID entries in ascending numeric order, a process occupying a high PID can use inotify events to determine when the process list is being scanned, and fork/exec to obtain a lower PID, thus avoiding enumeration. An unprivileged attacker can hide a process from procps-ng's utilities by exploiting a race condition in reading /proc/PID entries.             STATEMENT: The /proc filesystem is not a reliable mechanism to account for processes running on a system, as it is unable to offer snapshot semantics. Short-lived processes have always been able to escape detection by tools that monitor /proc. This CVE simply identifies a reliable way to do so using inotify. Process accounting for security purposes, or with a requirement to record very short-running processes and those attempting to evade detection, should be performed with more robust methods such as auditd(8) (the Linux Audit Daemon) or systemtap.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1121",
							Severity:      "Medium",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         2.9,
										"Score":               4.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:N/I:P/A:N",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         3.6,
										"Score":               5.9,
										"Vectors":             "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
									},
									"LastModifiedDateTime": "2020-06-30T16:15Z",
									"PublishedDateTime":    "2018-06-13T20:29Z",
								},
							},
						},
						{
							Name:          "CVE-2018-1123",
							NamespaceName: "centos:7",
							Description:   "DOCUMENTATION: Due to incorrect accounting when decoding and escaping Unicode data in procfs, ps is vulnerable to overflowing an mmap()ed region when formatting the process list for display. Since ps maps a guard page at the end of the buffer, impact is limited to a crash.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1123",
							Severity:      "High",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10,
										"ImpactScore":         2.9,
										"Score":               5,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2019-10-09T23:38Z",
									"PublishedDateTime":    "2018-05-23T14:29Z",
								},
							},
						},
						{
							Name:          "CVE-2018-1125",
							NamespaceName: "centos:7",
							Description:   "DOCUMENTATION: If a process inspected by pgrep has an argument longer than INT_MAX bytes, \"int bytes\" could wrap around back to a large positive int (rather than approaching zero), leading to a stack buffer overflow via strncat().                          MITIGATION: The procps suite on Red Hat Enterprise Linux is built with FORTIFY, which limits the impact of this stack overflow (and others like it) to a crash.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1125",
							Severity:      "High",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10,
										"ImpactScore":         2.9,
										"Score":               5,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2019-10-09T23:38Z",
									"PublishedDateTime":    "2018-05-23T14:29Z",
								},
							},
						},
					},
				},
			},
		},
		{
			image:    "us.gcr.io/stackrox-ci/qa/apache/server:latest",
			registry: "https://us.gcr.io",
			username: "_json_key",
			password: os.Getenv("GOOGLE_SA_CIRCLECI_SCANNER"),
			expectedFeatures: []v1.Feature{
				{
					Name:          "cron",
					NamespaceName: "ubuntu:14.04",
					VersionFormat: "dpkg",
					Version:       "3.0pl1-124ubuntu2",

					AddedBy: "sha256:bae382666908fd87a3a3646d7eb7176fa42226027d3256cac38ee0b79bdb0491",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:          "CVE-2017-9525",
							NamespaceName: "ubuntu:14.04",
							Description:   "In the cron package through 3.0pl1-128 on Debian, and through 3.0pl1-128ubuntu2 on Ubuntu, the postinst maintainer script allows for group-crontab-to-root privilege escalation via symlink attacks against unsafe usage of the chown and chmod programs.",
							Link:          "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2017-9525",
							Severity:      "Low",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 3.4,
										"ImpactScore":         10.0,
										"Score":               6.9,
										"Vectors":             "AV:L/AC:M/Au:N/C:C/I:C/A:C",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 0.8,
										"ImpactScore":         5.9,
										"Score":               6.7,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2019-03-21T23:29Z",
									"PublishedDateTime":    "2017-06-09T16:29Z",
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(testCase.image, func(t *testing.T) {
			verifyImageHasExpectedFeatures(cli, testCase.username, testCase.password, &types.ImageRequest{Image: testCase.image, Registry: testCase.registry}, testCase.expectedFeatures, t)
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
