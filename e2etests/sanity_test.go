// +build e2e

package e2etests

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/clairify/client"
	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stackrox/scanner/pkg/component"
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
	require.NotEqual(t, -1, candidateIdx, "Feature %+v not in list", featureToFind)
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

func verifyImageHasExpectedFeatures(t *testing.T, client *client.Clairify, username, password, source string, imageRequest *types.ImageRequest, checkContainsOnly bool, expectedFeatures, unexpectedFeatures []v1.Feature) {
	img, err := client.AddImage(username, password, imageRequest)
	require.NoError(t, err)

	env, err := client.RetrieveImageDataBySHA(img.SHA, true, true)
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

			if !checkContainsOnly {
				if len(matching.Vulnerabilities) != len(feature.Vulnerabilities) {
					matchingBytes, _ := json.MarshalIndent(matching.Vulnerabilities, "", "  ")
					featureVulnsBytes, _ := json.MarshalIndent(feature.Vulnerabilities, "", "  ")
					fmt.Printf("Matching: %s\n", matchingBytes)
					fmt.Printf("Feature: %s\n", featureVulnsBytes)
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
		})
	}

	for _, feature := range unexpectedFeatures {
		assert.Nil(t, getMatchingFeature(t, env.Layer.Features, feature, true))
	}
}

func TestImageSanity(t *testing.T) {
	cli := client.New(getScannerHTTPEndpoint(t), true)

	for _, testCase := range []struct {
		image              string
		registry           string
		username, password string
		source             string
		expectedFeatures   []v1.Feature
		unexpectedFeatures []v1.Feature
		checkContainsOnly  bool
	}{
		{
			image:    "docker.io/library/nginx:1.10",
			registry: "https://registry-1.docker.io",
			source:   "NVD",
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
			source:   "NVD",
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
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
										"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
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
			source:   "Red Hat",
			expectedFeatures: []v1.Feature{
				{
					Name:          "procps-ng",
					NamespaceName: "rhel:7",
					VersionFormat: "rpm",
					Version:       "3.3.10-26.el7",
					// The following CVE's are marked as "Won't Fix". Ensure Certified RHEL Scanning
					// catches them.
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:          "CVE-2018-1121",
							NamespaceName: "rhel:7",
							Description:   "DOCUMENTATION: Since the kernel's proc_pid_readdir() returns PID entries in ascending numeric order, a process occupying a high PID can use inotify events to determine when the process list is being scanned, and fork/exec to obtain a lower PID, thus avoiding enumeration. An unprivileged attacker can hide a process from procps-ng's utilities by exploiting a race condition in reading /proc/PID entries.             STATEMENT: The /proc filesystem is not a reliable mechanism to account for processes running on a system, as it is unable to offer snapshot semantics. Short-lived processes have always been able to escape detection by tools that monitor /proc. This CVE simply identifies a reliable way to do so using inotify. Process accounting for security purposes, or with a requirement to record very short-running processes and those attempting to evade detection, should be performed with more robust methods such as auditd(8) (the Linux Audit Daemon) or systemtap.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1121",
							Severity:      "Low",
							Metadata: map[string]interface{}{
								"Red Hat": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 0.0,
										"ImpactScore":         0.0,
										"Score":               0.0,
										"Vectors":             "",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.3,
										"ImpactScore":         2.5,
										"Score":               3.9,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L",
									},
									"PublishedDateTime": "2018-05-17T17:00:00Z",
								},
							},
						},
						{
							Name:          "CVE-2018-1123",
							NamespaceName: "rhel:7",
							Description:   "DOCUMENTATION: Due to incorrect accounting when decoding and escaping Unicode data in procfs, ps is vulnerable to overflowing an mmap()ed region when formatting the process list for display. Since ps maps a guard page at the end of the buffer, impact is limited to a crash.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1123",
							Severity:      "Low",
							Metadata: map[string]interface{}{
								"Red Hat": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 0.0,
										"ImpactScore":         0.0,
										"Score":               0.0,
										"Vectors":             "",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.3,
										"ImpactScore":         2.5,
										"Score":               3.9,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L",
									},
									"PublishedDateTime": "2018-05-17T17:00:00Z",
								},
							},
						},
						{
							Name:          "CVE-2018-1125",
							NamespaceName: "rhel:7",
							Description:   "DOCUMENTATION: If a process inspected by pgrep has an argument longer than INT_MAX bytes, \"int bytes\" could wrap around back to a large positive int (rather than approaching zero), leading to a stack buffer overflow via strncat().                          MITIGATION: The procps suite on Red Hat Enterprise Linux is built with FORTIFY, which limits the impact of this stack overflow (and others like it) to a crash.",
							Link:          "https://access.redhat.com/security/cve/CVE-2018-1125",
							Severity:      "Medium",
							Metadata: map[string]interface{}{
								"Red Hat": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 0.0,
										"ImpactScore":         0.0,
										"Score":               0.0,
										"Vectors":             "",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.8,
										"ImpactScore":         2.5,
										"Score":               4.4,
										"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
									},
									"PublishedDateTime": "2018-05-17T17:00:00Z",
								},
							},
						},
					},
					AddedBy: "sha256:c8d67acdb2ffaebd638cf55a8fccc63693211060670aa7f0ea1d65b5d2c674dd",
				},
			},
		},
		{
			image:    "us.gcr.io/stackrox-ci/qa/apache/server:latest",
			registry: "https://us.gcr.io",
			username: "_json_key",
			password: os.Getenv("GOOGLE_SA_CIRCLECI_SCANNER"),
			source:   "NVD",
			expectedFeatures: []v1.Feature{
				{
					Name:          "cron",
					NamespaceName: "ubuntu:14.04",
					VersionFormat: "dpkg",
					Version:       "3.0pl1-124ubuntu2",
					AddedBy:       "sha256:bae382666908fd87a3a3646d7eb7176fa42226027d3256cac38ee0b79bdb0491",
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
		{
			image:    "mcr.microsoft.com/dotnet/core/runtime:3.1.2",
			registry: "https://mcr.microsoft.com",
			source:   "NVD",
			expectedFeatures: []v1.Feature{
				{
					Name:          "microsoft.netcore.app",
					Version:       "3.1.2",
					VersionFormat: component.DotNetCoreRuntimeSourceType.String(),
					Location:      "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.2/",
					AddedBy:       "sha256:b48f8e1b0b06887c382543e23275911a388c1010e3436dc9b708ef29885bb594",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:        "CVE-2020-1108",
							Description: "A denial of service vulnerability exists when .NET Core or .NET Framework improperly handles web requests, aka '.NET Core & .NET Framework Denial of Service Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1108",
							FixedBy:     "3.1.5",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
										"Score":               5.0,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2020-06-05T19:53:00Z",
									"PublishedDateTime":    "2020-05-21T23:15:00Z",
								},
							},
						},
						{
							Name:        "CVE-2020-1147",
							Description: "A remote code execution vulnerability exists in .NET Framework, Microsoft SharePoint, and Visual Studio when the software fails to check the source markup of XML file input, aka '.NET Framework, SharePoint Server, and Visual Studio Remote Code Execution Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1147",
							FixedBy:     "3.1.6",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 1.8,
										"ImpactScore":         5.9,
										"Score":               7.8,
										"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-08-20T15:15Z",
									"PublishedDateTime":    "2020-07-14T23:15Z",
								},
							},
						},
						{
							Name:        "CVE-2021-1721",
							Description: ".NET Core and Visual Studio Denial of Service Vulnerability",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-1721",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         2.9,
										"Score":               4.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.8,
										"ImpactScore":         3.6,
										"Score":               6.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2021-03-01T16:34Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.12",
						},
						{
							Name:        "CVE-2021-1723",
							Description: "ASP.NET Core and Visual Studio Denial of Service Vulnerability",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-1723",
							FixedBy:     "3.1.11",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
										"Score":               5.0,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2021-01-25T19:54Z",
									"PublishedDateTime":    "2021-01-12T20:15Z",
								},
							},
						},
						{
							Name:        "CVE-2021-24112",
							Description: ".NET Core Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26701.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-24112",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         6.4,
										"Score":               7.5,
										"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         5.9,
										"Score":               9.8,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2021-03-01T16:34Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.12",
						},
						{
							Name:        "CVE-2021-26701",
							Description: ".NET Core Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-24112.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-26701",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         6.4,
										"Score":               7.5,
										"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         5.9,
										"Score":               9.8,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2021-03-12T13:25Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.13",
						},
					},
				},
			},
		},
		{
			image:    "mcr.microsoft.com/dotnet/core/sdk:3.1.100@sha256:091126a93870729f4438ee7ed682ed98639a89acebed40409af90f84302c48dd",
			registry: "https://mcr.microsoft.com",
			source:   "NVD",
			expectedFeatures: []v1.Feature{
				{
					Name:          "microsoft.aspnetcore.app",
					VersionFormat: "DotNetCoreRuntimeSourceType",
					Version:       "3.1.0",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:        "CVE-2020-0602",
							Description: "A denial of service vulnerability exists when ASP.NET Core improperly handles web requests, aka 'ASP.NET Core Denial of Service Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-0602",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-01-14T23:15Z",
									"LastModifiedDateTime": "2020-01-17T02:49Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										"Score":               5.0,
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										"Score":               7.5,
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
									},
								},
							},
							FixedBy: "3.1.1",
						},
						{
							Name:        "CVE-2020-0603",
							Description: "A remote code execution vulnerability exists in ASP.NET Core software when the software fails to handle objects in memory.An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user, aka 'ASP.NET Core Remote Code Execution Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-0603",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-01-14T23:15Z",
									"LastModifiedDateTime": "2020-01-17T19:22Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:M/Au:N/C:C/I:C/A:C",
										"Score":               9.3,
										"ExploitabilityScore": 8.6,
										"ImpactScore":         10.0,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										"Score":               8.8,
										"ExploitabilityScore": 2.8,
										"ImpactScore":         5.9,
									},
								},
							},
							FixedBy: "3.1.1",
						},
						{
							Name:        "CVE-2020-1045",
							Description: "A security feature bypass vulnerability exists in the way Microsoft ASP.NET Core parses encoded cookie names.The ASP.NET Core cookie parser decodes entire cookie strings which could allow a malicious attacker to set a second cookie with the name being percent encoded.The security update addresses the vulnerability by fixing the way the ASP.NET Core cookie parser handles encoded names., aka 'Microsoft ASP.NET Core Security Feature Bypass Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1045",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-09-11T17:15Z",
									"LastModifiedDateTime": "2020-10-02T03:15Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:P/A:N",
										"Score":               5.0,
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
										"Score":               7.5,
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
									},
								},
							},
							FixedBy: "3.1.8",
						},
						{
							Name:        "CVE-2020-1161",
							Description: "A denial of service vulnerability exists when ASP.NET Core improperly handles web requests, aka 'ASP.NET Core Denial of Service Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1161",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-05-21T23:15Z",
									"LastModifiedDateTime": "2020-05-27T18:54Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										"Score":               5.0,
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										"Score":               7.5,
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
									},
								},
							},
							FixedBy: "3.1.4",
						},
						{
							Name:        "CVE-2020-1597",
							Description: "A denial of service vulnerability exists when ASP.NET Core improperly handles web requests, aka 'ASP.NET Core Denial of Service Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1597",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-08-17T19:15Z",
									"LastModifiedDateTime": "2020-09-25T20:15Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										"Score":               5.0,
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										"Score":               7.5,
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
									},
								},
							},
							FixedBy: "3.1.7",
						},
						{
							Name:        "CVE-2021-1723",
							Description: "ASP.NET Core and Visual Studio Denial of Service Vulnerability",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-1723",
							FixedBy:     "3.1.11",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
										"Score":               5.0,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2021-01-25T19:54Z",
									"PublishedDateTime":    "2021-01-12T20:15Z",
								},
							},
						},
					},
					AddedBy:  "sha256:5bd47e7e8ad7786db14c79827b543615728f0e27567f5b05d4c13db29bb24c7a",
					Location: "usr/share/dotnet/shared/Microsoft.AspNetCore.App/3.1.0/",
				},
				{
					Name:          "microsoft.netcore.app",
					VersionFormat: "DotNetCoreRuntimeSourceType",
					Version:       "3.1.0",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:        "CVE-2020-0605",
							Description: "A remote code execution vulnerability exists in .NET software when the software fails to check the source markup of a file.An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user, aka '.NET Framework Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0606.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-0605",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-01-14T23:15Z",
									"LastModifiedDateTime": "2020-01-21T21:22Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:M/Au:N/C:C/I:C/A:C",
										"Score":               9.3,
										"ExploitabilityScore": 8.6,
										"ImpactScore":         10.0,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										"Score":               8.8,
										"ExploitabilityScore": 2.8,
										"ImpactScore":         5.9,
									},
								},
							},
							FixedBy: "3.1.1",
						},
						{
							Name:        "CVE-2020-0606",
							Description: "A remote code execution vulnerability exists in .NET software when the software fails to check the source markup of a file.An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user, aka '.NET Framework Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0605.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-0606",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-01-14T23:15Z",
									"LastModifiedDateTime": "2020-01-17T03:03Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:M/Au:N/C:C/I:C/A:C",
										"Score":               9.3,
										"ExploitabilityScore": 8.6,
										"ImpactScore":         10.0,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										"Score":               8.8,
										"ExploitabilityScore": 2.8,
										"ImpactScore":         5.9,
									},
								},
							},
							FixedBy: "3.1.1",
						},
						{
							Name:        "CVE-2020-1108",
							Description: "A denial of service vulnerability exists when .NET Core or .NET Framework improperly handles web requests, aka '.NET Core & .NET Framework Denial of Service Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1108",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-05-21T23:15Z",
									"LastModifiedDateTime": "2020-06-05T19:53Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										"Score":               5.0,
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										"Score":               7.5,
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
									},
								},
							},
							FixedBy: "3.1.5",
						},
						{
							Name:        "CVE-2020-1147",
							Description: "A remote code execution vulnerability exists in .NET Framework, Microsoft SharePoint, and Visual Studio when the software fails to check the source markup of XML file input, aka '.NET Framework, SharePoint Server, and Visual Studio Remote Code Execution Vulnerability'.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1147",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"PublishedDateTime":    "2020-07-14T23:15Z",
									"LastModifiedDateTime": "2020-08-20T15:15Z",
									"CVSSv2": map[string]interface{}{
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
										"Score":               6.8,
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
									},
									"CVSSv3": map[string]interface{}{
										"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										"Score":               7.8,
										"ExploitabilityScore": 1.8,
										"ImpactScore":         5.9,
									},
								},
							},
							FixedBy: "3.1.6",
						},
						{
							Name:        "CVE-2021-1721",
							Description: ".NET Core and Visual Studio Denial of Service Vulnerability",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-1721",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         2.9,
										"Score":               4.3,
										"Vectors":             "AV:N/AC:M/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.8,
										"ImpactScore":         3.6,
										"Score":               6.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2021-03-01T16:34Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.12",
						},
						{
							Name:        "CVE-2021-1723",
							Description: "ASP.NET Core and Visual Studio Denial of Service Vulnerability",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-1723",
							FixedBy:     "3.1.11",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
										"Score":               5.0,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
									"LastModifiedDateTime": "2021-01-25T19:54Z",
									"PublishedDateTime":    "2021-01-12T20:15Z",
								},
							},
						},
						{
							Name:        "CVE-2021-24112",
							Description: ".NET Core Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26701.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-24112",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         6.4,
										"Score":               7.5,
										"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         5.9,
										"Score":               9.8,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2021-03-01T16:34Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.12",
						},
						{
							Name:        "CVE-2021-26701",
							Description: ".NET Core Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-24112.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-26701",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         6.4,
										"Score":               7.5,
										"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         5.9,
										"Score":               9.8,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2021-03-12T13:25Z",
									"PublishedDateTime":    "2021-02-25T23:15Z",
								},
							},
							FixedBy: "3.1.13",
						},
					},
					AddedBy:  "sha256:5bd47e7e8ad7786db14c79827b543615728f0e27567f5b05d4c13db29bb24c7a",
					Location: "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.0/",
				},
			},
		},
		{
			// Deletes directory containing jackson-databind:2.6.6.
			image:             "docker.io/stackrox/sandbox:scannerremovejar",
			registry:          "https://registry-1.docker.io",
			username:          os.Getenv("DOCKER_IO_PULL_USERNAME"),
			password:          os.Getenv("DOCKER_IO_PULL_PASSWORD"),
			source:            "NVD",
			checkContainsOnly: true,
			expectedFeatures: []v1.Feature{
				{
					Name:          "jackson-databind",
					VersionFormat: "JavaSourceType",
					Version:       "2.9.10.4",
					Vulnerabilities: []v1.Vulnerability{
						{
							Name:        "CVE-2020-14060",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.xalan.lib.sql.JNDIConnectionPool (aka apache/drill).",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-14060",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"LastModifiedDateTime": "2020-10-20T22:15Z",
									"PublishedDateTime":    "2020-06-14T21:15Z",
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
							},
							FixedBy: "2.9.10.5",
						},
						{
							Name:        "CVE-2020-14061",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oracle.jms.AQjmsQueueConnectionFactory, oracle.jms.AQjmsXATopicConnectionFactory, oracle.jms.AQjmsTopicConnectionFactory, oracle.jms.AQjmsXAQueueConnectionFactory, and oracle.jms.AQjmsXAConnectionFactory (aka weblogic/oracle-aqjms).",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-14061",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-10-20T22:15Z",
									"PublishedDateTime":    "2020-06-14T20:15Z",
								},
							},
							FixedBy: "2.9.10.5",
						},
						{
							Name:        "CVE-2020-14062",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool (aka xalan2).",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-14062",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-10-20T22:15Z",
									"PublishedDateTime":    "2020-06-14T20:15Z",
								},
							},
							FixedBy: "2.9.10.5",
						},
						{
							Name:        "CVE-2020-14195",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-14195",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-10-20T22:15Z",
									"PublishedDateTime":    "2020-06-16T16:15Z",
								},
							},
							FixedBy: "2.9.10.5",
						},
						{
							Name:        "CVE-2020-24616",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-24616",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-09-04T14:59Z",
									"PublishedDateTime":    "2020-08-25T18:15Z",
								},
							},
							FixedBy: "2.9.10.6",
						},
						{
							Name:        "CVE-2020-24750",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to com.pastdev.httpcomponents.configuration.JndiConfiguration.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-24750",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-10-09T12:15Z",
									"PublishedDateTime":    "2020-09-17T19:15Z",
								},
							},
							FixedBy: "2.9.10.6",
						},
						{
							Name:        "CVE-2020-25649",
							Description: "A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly. This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-25649",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 10.0,
										"ImpactScore":         2.9,
										"Score":               5.0,
										"Vectors":             "AV:N/AC:L/Au:N/C:N/I:P/A:N",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 3.9,
										"ImpactScore":         3.6,
										"Score":               7.5,
										"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
									},
									"LastModifiedDateTime": "2020-12-07T15:08Z",
									"PublishedDateTime":    "2020-12-03T17:15Z",
								},
							},
							FixedBy: "2.9.10.7",
						},

						{
							Name:        "CVE-2020-35490",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-35490",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-12-18T19:32Z",
									"PublishedDateTime":    "2020-12-17T19:15Z",
								},
							},
							FixedBy: "2.9.10.8",
						},
						{
							Name:        "CVE-2020-35491",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.",
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-35491",
							Metadata: map[string]interface{}{
								"NVD": map[string]interface{}{
									"CVSSv2": map[string]interface{}{
										"ExploitabilityScore": 8.6,
										"ImpactScore":         6.4,
										"Score":               6.8,
										"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
									},
									"CVSSv3": map[string]interface{}{
										"ExploitabilityScore": 2.2,
										"ImpactScore":         5.9,
										"Score":               8.1,
										"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
									"LastModifiedDateTime": "2020-12-18T19:27Z",
									"PublishedDateTime":    "2020-12-17T19:15Z",
								},
							},
							FixedBy: "2.9.10.8",
						},
					},
					AddedBy:  "sha256:36e8e9714b9a509fae9e515ff16237928c3d809f5ae228b14d2f7d7605c02623",
					Location: "jars/jackson-databind-2.9.10.4.jar",
				},
			},
			unexpectedFeatures: []v1.Feature{
				{
					Name:          "jackson-databind",
					VersionFormat: "JavaSourceType",
					Version:       "2.6.6",
				},
			},
		},
		{
			// Deletes fatjar containing zookeeper and guava, and deletes standalone jar containing netty.
			image:    "docker.io/stackrox/sandbox:zookeeper-fatjar-remove",
			registry: "https://registry-1.docker.io",
			username: os.Getenv("DOCKER_IO_PULL_USERNAME"),
			password: os.Getenv("DOCKER_IO_PULL_PASSWORD"),
			source:   "NVD",
			unexpectedFeatures: []v1.Feature{
				{
					Name:          "zookeeper",
					VersionFormat: "JavaSourceType",
					Version:       "3.4.13",
				},
				{
					Name:          "guava",
					VersionFormat: "JavaSourceType",
					Version:       "18.0",
				},
				{
					Name:          "netty",
					VersionFormat: "JavaSourceType",
					Version:       "3.10.6.final",
				},
			},
		},
		{
			// OCI media type manifest.
			image:    "docker.io/stackrox/sandbox:oci-manifest",
			registry: "https://registry-1.docker.io",
			username: os.Getenv("DOCKER_IO_PULL_USERNAME"),
			password: os.Getenv("DOCKER_IO_PULL_PASSWORD"),
			source:   "NVD",
		},
	} {
		t.Run(testCase.image, func(t *testing.T) {
			verifyImageHasExpectedFeatures(t, cli, testCase.username, testCase.password, testCase.source, &types.ImageRequest{Image: testCase.image, Registry: testCase.registry}, testCase.checkContainsOnly, testCase.expectedFeatures, testCase.unexpectedFeatures)
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
