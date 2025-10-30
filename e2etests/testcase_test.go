//go:build e2e || slim_e2e
// +build e2e slim_e2e

package e2etests

import (
	"os"

	apiV1 "github.com/stackrox/scanner/api/v1"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/features"
)

type testCase struct {
	image              string
	registry           string
	username, password string
	source             string
	namespace          string
	expectedFeatures   []apiV1.Feature
	unexpectedFeatures []apiV1.Feature
	// This specifies that the features only need to contain at least the vulnerabilities specified.
	onlyCheckSpecifiedVulns  bool
	uncertifiedRHEL          bool
	checkProvidedExecutables bool
	// If assigned a features.FeatureFlag, only enable the test if it is enabled.
	requiredFeatureFlag features.FeatureFlag
}

func init() {
	enabledCases := testCases[:0]
	for _, tc := range testCases {
		// Filter out test cases that depend on disabled feature flags.
		if tc.requiredFeatureFlag != nil && !tc.requiredFeatureFlag.Enabled() {
			continue
		}
		enabledCases = append(enabledCases, tc)
	}
	testCases = enabledCases
}

// testCases defines all the E2E test cases.
// Not all defined test cases will be available for use.
// Cases which rely on a disabled feature flag are filtered out.
var testCases = []testCase{
	{
		image:                    "quay.io/rhacs-eng/qa:ubuntu-16.04",
		registry:                 "https://quay.io",
		username:                 os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                 os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                   "NVD",
		onlyCheckSpecifiedVulns:  true,
		checkProvidedExecutables: true,
		namespace:                "ubuntu:16.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "lz4",
				NamespaceName: "ubuntu:16.04",
				VersionFormat: "dpkg",
				Version:       "0.0~r131-2ubuntu2",
				// The only provided executable file is a symlink, so there are no regular executable files.
				Executables: []*v1.Executable{},
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-3520",
						NamespaceName: "ubuntu:16.04",
						Description:   "There's a flaw in lz4. An attacker who submits a crafted file to an application linked with lz4 may be able to trigger an integer overflow, leading to calling of memmove() on a negative size argument, causing an out-of-bounds write and/or a crash. The greatest impact of this flaw is to availability, with some potential impact to confidentiality and integrity as well.",
						Link:          "https://ubuntu.com/security/CVE-2021-3520",
						Severity:      "Moderate",
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
							},
						},
						FixedBy: "0.0~r131-2ubuntu2+esm1",
					},
				},
				AddedBy: "sha256:58690f9b18fca6469a14da4e212c96849469f9b1be6661d2342a4bf01774aa50",
				FixedBy: "0.0~r131-2ubuntu2+esm1",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:nginx-1.10",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "debian:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:            "diffutils",
				NamespaceName:   "debian:8",
				VersionFormat:   "dpkg",
				Version:         "1:3.3-1",
				Vulnerabilities: nil,
				AddedBy:         "sha256:b87f0972440570029cb139e9ea513c3b9aad24cc0051d7c50226dd7f345af109",
			},
			{
				Name:          "coreutils",
				NamespaceName: "debian:8",
				VersionFormat: "dpkg",
				Version:       "8.23-4",
				Vulnerabilities: []apiV1.Vulnerability{
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
						Severity:      "Low",
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
				AddedBy: "sha256:b87f0972440570029cb139e9ea513c3b9aad24cc0051d7c50226dd7f345af109",
			},
		},
	},
	{
		image:                    "quay.io/rhacs-eng/qa:kaizheh-apache-struts2-cve-2017-5638-latest",
		registry:                 "https://quay.io",
		username:                 os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                 os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                   "NVD",
		checkProvidedExecutables: true,
		namespace:                "debian:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apt",
				NamespaceName: "debian:8",
				VersionFormat: "dpkg",
				Version:       "1.0.9.8.4",
				Executables: []*v1.Executable{
					{
						Path: "/etc/cron.daily/apt",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/etc/kernel/postinst.d/apt-auto-removal",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/usr/share/bug/apt/script",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/xz",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/bzip2",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/lzma",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/ssh",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/dpkg/methods/apt/update",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/usr/lib/dpkg/methods/apt/setup",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/usr/lib/dpkg/methods/apt/install",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
					{
						Path: "/usr/lib/apt/apt-helper",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/cdrom",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/copy",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/file",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/ftp",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/gpgv",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/gzip",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/http",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/mirror",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/rred",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/lib/apt/methods/rsh",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-cache",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-cdrom",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-config",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-get",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-mark",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
							{Name: "bzip2", Version: "1.0.6-7"},
							{Name: "gcc-4.9", Version: "4.9.2-10"},
							{Name: "glibc", Version: "2.19-18+deb8u10"},
							{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
							{Name: "zlib", Version: "1:1.2.8.dfsg-2"},
						},
					},
					{
						Path: "/usr/bin/apt-key",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apt", Version: "1.0.9.8.4"},
						},
					},
				},
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2011-3374",
						NamespaceName: "debian:8",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2011-3374",
						Severity:      "Low",
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
						Severity:      "Important",
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
						Severity:      "Moderate",
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
				AddedBy: "sha256:a725810793221ffd6cc25a40bf9439d1bc10605735ca4da28af1e712ab8420de",
				FixedBy: "1.0.9.8.6",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:anchore-anchore-engine-v0.5.0",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "Red Hat",
		namespace: "centos:7",
		// This image is older than June 2020, so we need to explicitly request for an uncertified scan.
		uncertifiedRHEL:          true,
		checkProvidedExecutables: true,
		onlyCheckSpecifiedVulns:  true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "procps-ng",
				NamespaceName: "centos:7",
				VersionFormat: "rpm",
				Version:       "3.3.10-26.el7",
				Executables: []*v1.Executable{
					{
						Path: "/usr/bin/free",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/pgrep",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/pkill",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/pmap",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/ps",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/pwdx",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/skill",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/slabtop",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "ncurses-libs", Version: "5.9-14.20130511.el7_4"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/snice",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/tload",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/top",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "ncurses-libs", Version: "5.9-14.20130511.el7_4"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/uptime",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/vmstat",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/w",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/bin/watch",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "ncurses-libs", Version: "5.9-14.20130511.el7_4"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/lib64/libprocps.so.4.0.0",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/lib64/libprocps.so.4",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
					{
						Path: "/usr/sbin/sysctl",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "bzip2-libs", Version: "1.0.6-13.el7"},
							{Name: "elfutils-libelf", Version: "0.176-2.el7"},
							{Name: "elfutils-libs", Version: "0.176-2.el7"},
							{Name: "glibc", Version: "2.17-292.el7"},
							{Name: "libattr", Version: "2.4.46-13.el7"},
							{Name: "libcap", Version: "2.22-10.el7"},
							{Name: "libgcc", Version: "4.8.5-39.el7"},
							{Name: "libgcrypt", Version: "1.5.3-14.el7"},
							{Name: "libgpg-error", Version: "1.12-3.el7"},
							{Name: "libselinux", Version: "2.5-14.1.el7"},
							{Name: "lz4", Version: "1.7.5-3.el7"},
							{Name: "pcre", Version: "8.32-17.el7"},
							{Name: "procps-ng", Version: "3.3.10-26.el7"},
							{Name: "systemd-libs", Version: "219-67.el7_7.1"},
							{Name: "xz-libs", Version: "5.2.2-1.el7"},
							{Name: "zlib", Version: "1.2.7-18.el7"},
						},
					},
				},
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2018-1121",
						NamespaceName: "centos:7",
						Description:   "DOCUMENTATION: Since the kernel's proc_pid_readdir() returns PID entries in ascending numeric order, a process occupying a high PID can use inotify events to determine when the process list is being scanned, and fork/exec to obtain a lower PID, thus avoiding enumeration. An unprivileged attacker can hide a process from procps-ng's utilities by exploiting a race condition in reading /proc/PID entries.              STATEMENT: The /proc filesystem is not a reliable mechanism to account for processes running on a system, as it is unable to offer snapshot semantics. Short-lived processes have always been able to escape detection by tools that monitor /proc. This CVE simply identifies a reliable way to do so using inotify. Process accounting for security purposes, or with a requirement to record very short-running processes and those attempting to evade detection, should be performed with more robust methods such as auditd(8) (the Linux Audit Daemon) or systemtap. Because an attacker can achieve similar results whether this vulnerability is present or not, Red Hat assesses its impact as Low.",
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
							},
						},
					},
					{
						Name:          "CVE-2018-1123",
						NamespaceName: "centos:7",
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
							},
						},
					},
					{
						Name:          "CVE-2018-1125",
						NamespaceName: "centos:7",
						Description:   "DOCUMENTATION: If a process inspected by pgrep has an argument longer than INT_MAX bytes, \"int bytes\" could wrap around back to a large positive int (rather than approaching zero), leading to a stack buffer overflow via strncat().                          MITIGATION: The procps suite on Red Hat Enterprise Linux is built with FORTIFY, which limits the impact of this stack overflow (and others like it) to a crash.",
						Link:          "https://access.redhat.com/security/cve/CVE-2018-1125",
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
									"ExploitabilityScore": 1.8,
									"ImpactScore":         2.5,
									"Score":               4.4,
									"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
								},
							},
						},
					},
				},
				AddedBy: "sha256:3a7df7a31d0379653de0a8eb812af69dbaa65e84e6dfa8da0162d23a2da5b26d",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:apache-server-scannerci",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "ubuntu:14.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "pam",
				NamespaceName: "ubuntu:14.04",
				VersionFormat: "dpkg",
				Version:       "1.1.8-1ubuntu2.2",
				AddedBy:       "sha256:bae382666908fd87a3a3646d7eb7176fa42226027d3256cac38ee0b79bdb0491",
				FixedBy:       "1.1.8-1ubuntu2.2+esm4",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2022-28321",
						NamespaceName: "ubuntu:14.04",
						Description:   "The Linux-PAM package before 1.5.2-6.1 for openSUSE Tumbleweed allows authentication bypass for SSH logins. The pam_access.so module doesn't correctly restrict login if a user tries to connect from an IP address that is not resolvable via DNS. In such conditions, a user with denied access to a machine can still get access. NOTE: the relevance of this issue is largely limited to openSUSE Tumbleweed and openSUSE Factory; it does not affect Linux-PAM upstream.",
						Link:          "https://ubuntu.com/security/CVE-2022-28321",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": float64(0),
									"ImpactScore":         float64(0),
									"Score":               float64(0),
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"LastModifiedDateTime": "2024-11-21T06:57:00Z",
								"PublishedDateTime":    "2022-09-19T22:15:00Z",
							},
						},
						FixedBy: "1.1.8-1ubuntu2.2+esm1",
					},
					{
						Name:          "CVE-2024-22365",
						NamespaceName: "ubuntu:14.04",
						Description:   "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
						Link:          "https://ubuntu.com/security/CVE-2024-22365",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": float64(0),
									"ImpactScore":         float64(0),
									"Score":               float64(0),
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								},
								"LastModifiedDateTime": "2024-11-21T08:56:00Z",
								"PublishedDateTime":    "2024-02-06T08:15:00Z",
							},
						},
						FixedBy: "1.1.8-1ubuntu2.2+esm4",
					},
				},
			},
		},
	},
	{
		image:                   "mcr.microsoft.com/dotnet/core/runtime:3.1.2",
		registry:                "https://mcr.microsoft.com",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "debian:10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "microsoft.netcore.app",
				Version:       "3.1.2",
				VersionFormat: component.DotNetCoreRuntimeSourceType.String(),
				Location:      "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.2/",
				AddedBy:       "sha256:b48f8e1b0b06887c382543e23275911a388c1010e3436dc9b708ef29885bb594",
				FixedBy:       "3.1.32",
				Vulnerabilities: []apiV1.Vulnerability{
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
						Severity: "Important",
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
						Severity: "Important",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.8,
								// 	"ImpactScore":         3.6,
								// 	"Score":               6.5,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
								// },
								"LastModifiedDateTime": "2021-03-01T16:34Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.12",
						Severity: "Moderate",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 3.9,
								// 	"ImpactScore":         3.6,
								// 	"Score":               7.5,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								// },
								"LastModifiedDateTime": "2021-01-25T19:54Z",
								"PublishedDateTime":    "2021-01-12T20:15Z",
							},
						},
						Severity: "Moderate",
					},
					{
						Name:        "CVE-2021-24112",
						Description: ".NET Core Remote Code Execution Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-24112",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         6.4,
									"Score":               7.5,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.2,
								// 	"ImpactScore":         5.9,
								// 	"Score":               8.1,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T17:15Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.12",
						Severity: "Important",
					},
					{
						Name:        "CVE-2021-26701",
						Description: ".NET Core Remote Code Execution Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-26701",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         6.4,
									"Score":               7.5,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.2,
								// 	"ImpactScore":         5.9,
								// 	"Score":               8.1,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T17:16Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.13",
						Severity: "Important",
					},
					{
						Name:        "CVE-2021-31204",
						Description: ".NET and Visual Studio Elevation of Privilege Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-31204",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         6.4,
									"Score":               4.6,
									"Vectors":             "AV:L/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 1.3,
								// 	"ImpactScore":         5.9,
								// 	"Score":               7.3,
								// 	"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T00:15Z",
								"PublishedDateTime":    "2021-05-11T19:15Z",
							},
						},
						FixedBy:  "3.1.15",
						Severity: "Moderate",
					},
				},
			},
		},
	},
	{
		image:                   "mcr.microsoft.com/dotnet/core/sdk:3.1.100@sha256:091126a93870729f4438ee7ed682ed98639a89acebed40409af90f84302c48dd",
		registry:                "https://mcr.microsoft.com",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "debian:10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "microsoft.aspnetcore.app",
				VersionFormat: component.DotNetCoreRuntimeSourceType.String(),
				Version:       "3.1.0",
				Vulnerabilities: []apiV1.Vulnerability{
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
						FixedBy:  "3.1.1",
						Severity: "Important",
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
						FixedBy:  "3.1.1",
						Severity: "Important",
					},
					{
						Name:        "CVE-2020-1045",
						Description: "<p>A security feature bypass vulnerability exists in the way Microsoft ASP.NET Core parses encoded cookie names.</p>\n<p>The ASP.NET Core cookie parser decodes entire cookie strings which could allow a malicious attacker to set a second cookie with the name being percent encoded.</p>\n<p>The security update addresses the vulnerability by fixing the way the ASP.NET Core cookie parser handles encoded names.</p>\n",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
								// 	"Score":               7.5,
								// 	"ExploitabilityScore": 3.9,
								// 	"ImpactScore":         3.6,
								// },
							},
						},
						FixedBy:  "3.1.8",
						Severity: "Moderate",
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
						FixedBy:  "3.1.4",
						Severity: "Important",
					},
					{
						Name:        "CVE-2020-1597",
						Description: "A denial of service vulnerability exists when ASP.NET Core improperly handles web requests. An attacker who successfully exploited this vulnerability could cause a denial of service against an ASP.NET Core web application. The vulnerability can be exploited remotely, without authentication.\nA remote unauthenticated attacker could exploit this vulnerability by issuing specially crafted requests to the ASP.NET Core application.\nThe update addresses the vulnerability by correcting how the ASP.NET Core web application handles web requests.\n",
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
						FixedBy:  "3.1.7",
						Severity: "Important",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 3.9,
								// 	"ImpactScore":         3.6,
								// 	"Score":               7.5,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								// },
								"LastModifiedDateTime": "2021-01-25T19:54Z",
								"PublishedDateTime":    "2021-01-12T20:15Z",
							},
						},
						Severity: "Moderate",
					},
				},
				AddedBy:  "sha256:5bd47e7e8ad7786db14c79827b543615728f0e27567f5b05d4c13db29bb24c7a",
				Location: "usr/share/dotnet/shared/Microsoft.AspNetCore.App/3.1.0/",
				FixedBy:  "3.1.11",
			},
			{
				Name:          "microsoft.netcore.app",
				VersionFormat: "DotNetCoreRuntimeSourceType",
				Version:       "3.1.0",
				Vulnerabilities: []apiV1.Vulnerability{
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
						FixedBy:  "3.1.1",
						Severity: "Important",
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
						FixedBy:  "3.1.1",
						Severity: "Important",
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
						FixedBy:  "3.1.5",
						Severity: "Important",
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
						FixedBy:  "3.1.6",
						Severity: "Important",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.8,
								// 	"ImpactScore":         3.6,
								// 	"Score":               6.5,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
								// },
								"LastModifiedDateTime": "2021-03-01T16:34Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.12",
						Severity: "Moderate",
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
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 3.9,
								// 	"ImpactScore":         3.6,
								// 	"Score":               7.5,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								// },
								"LastModifiedDateTime": "2021-01-25T19:54Z",
								"PublishedDateTime":    "2021-01-12T20:15Z",
							},
						},
						Severity: "Moderate",
					},
					{
						Name:        "CVE-2021-24112",
						Description: ".NET Core Remote Code Execution Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-24112",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         6.4,
									"Score":               7.5,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.2,
								// 	"ImpactScore":         5.9,
								// 	"Score":               8.1,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T17:15Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.12",
						Severity: "Important",
					},
					{
						Name:        "CVE-2021-26701",
						Description: ".NET Core Remote Code Execution Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-26701",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         6.4,
									"Score":               7.5,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 2.2,
								// 	"ImpactScore":         5.9,
								// 	"Score":               8.1,
								// 	"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T17:15Z",
								"PublishedDateTime":    "2021-02-25T23:15Z",
							},
						},
						FixedBy:  "3.1.13",
						Severity: "Important",
					},
					{
						Name:        "CVE-2021-31204",
						Description: ".NET and Visual Studio Elevation of Privilege Vulnerability",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-31204",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         6.4,
									"Score":               4.6,
									"Vectors":             "AV:L/AC:L/Au:N/C:P/I:P/A:P",
								},
								// NVD stopped returning this
								// "CVSSv3": map[string]interface{}{
								// 	"ExploitabilityScore": 1.3,
								// 	"ImpactScore":         5.9,
								// 	"Score":               7.3,
								// 	"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
								// },
								"LastModifiedDateTime": "2023-12-29T00:15Z",
								"PublishedDateTime":    "2021-05-11T19:15Z",
							},
						},
						FixedBy:  "3.1.15",
						Severity: "Moderate",
					},
				},
				AddedBy:  "sha256:5bd47e7e8ad7786db14c79827b543615728f0e27567f5b05d4c13db29bb24c7a",
				Location: "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.0/",
				FixedBy:  "3.1.32",
			},
		},
	},
	{
		// Deletes directory containing jackson-databind:2.6.6.
		image:                   "quay.io/rhacs-eng/qa:sandbox-scannerremovejar",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:14.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "jackson-databind",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "2.9.10.4",
				Vulnerabilities: []apiV1.Vulnerability{
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
						FixedBy:  "2.9.10.5",
						Severity: "Important",
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
						FixedBy:  "2.9.10.5",
						Severity: "Important",
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
						FixedBy:  "2.9.10.5",
						Severity: "Important",
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
						FixedBy:  "2.9.10.5",
						Severity: "Important",
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
						FixedBy:  "2.9.10.6",
						Severity: "Important",
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
						FixedBy:  "2.9.10.6",
						Severity: "Important",
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
						FixedBy:  "2.9.10.7",
						Severity: "Important",
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
						FixedBy:  "2.9.10.8",
						Severity: "Important",
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
						FixedBy:  "2.9.10.8",
						Severity: "Important",
					},
					{
						Name:        "CVE-2020-36518",
						Description: "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-36518",
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
							},
						},
						FixedBy:  "2.12.6.1",
						Severity: "Important",
					},
				},
				AddedBy:  "sha256:36e8e9714b9a509fae9e515ff16237928c3d809f5ae228b14d2f7d7605c02623",
				Location: "jars/jackson-databind-2.9.10.4.jar",
				FixedBy:  "2.16.0",
			},
		},
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:          "jackson-databind",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "2.6.6",
			},
		},
	},
	{
		// Deletes fatjar containing zookeeper and guava, and deletes standalone jar containing netty.
		image:     "quay.io/rhacs-eng/qa:sandbox-zookeeper-fatjar-remove",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "alpine:v3.8",
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:          "zookeeper",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "3.4.13",
			},
			{
				Name:          "guava",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "18.0",
			},
			{
				Name:          "netty",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "3.10.6.final",
			},
		},
	},
	{
		// OCI media type manifest.
		image:     "quay.io/rhacs-eng/qa:sandbox-oci-manifest",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "ubuntu:16.04",
	},
	{
		// One of the images used for Red Hat Scanner Certification.
		image:                    "quay.io/rhacs-eng/qa:sandbox-jenkins-agent-maven-35-rhel7",
		registry:                 "https://quay.io",
		username:                 os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                 os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                   "Red Hat",
		onlyCheckSpecifiedVulns:  true,
		checkProvidedExecutables: true,
		namespace:                "rhel:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "rh-maven35-log4j12",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "1.2.17-19.2.el7.noarch",
				// This feature provides several JAR files, but they are either not executable or they are symlinks.
				Executables: []*v1.Executable{},
				AddedBy:     "sha256:4b4eac8c1d679c473379a42d37ec83b98bbafd8bb316200f53123f72d53bbb84",
			},
			{
				Name:          "rh-maven35-jackson-databind",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "2.7.6-2.10.el7.noarch",
				// This feature provides a JAR file that is not executable.
				Executables: []*v1.Executable{},
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2020:4173",
						NamespaceName: "rhel:7",
						Description:   "The jackson-databind package provides general data-binding functionality for Jackson, which works on top of Jackson core streaming API.\n\nSecurity Fix(es):\n\n* jackson-databind: Serialization gadgets in com.pastdev.httpcomponents.configuration.JndiConfiguration (CVE-2020-24750)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2020:4173",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         5.9,
									"Score":               8.1,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:2.7.6-2.11.el7",
					},
				},
				AddedBy: "sha256:4b4eac8c1d679c473379a42d37ec83b98bbafd8bb316200f53123f72d53bbb84",
				FixedBy: "2.7.6-2.12.el7",
			},
			{
				Name:          "vim-minimal",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "2:7.4.629-6.el7.x86_64",
				Executables: []*v1.Executable{
					{
						Path: "/usr/bin/vi",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "glibc", Version: "2.17-307.el7.1.i686"},
							{Name: "glibc", Version: "2.17-307.el7.1.x86_64"},
							{Name: "libacl", Version: "2.2.51-15.el7.x86_64"},
							{Name: "libattr", Version: "2.4.46-13.el7.i686"},
							{Name: "libattr", Version: "2.4.46-13.el7.x86_64"},
							{Name: "libselinux", Version: "2.5-15.el7.i686"},
							{Name: "libselinux", Version: "2.5-15.el7.x86_64"},
							{Name: "ncurses-libs", Version: "5.9-14.20130511.el7_4.x86_64"},
							{Name: "pcre", Version: "8.32-17.el7.i686"},
							{Name: "pcre", Version: "8.32-17.el7.x86_64"},
							{Name: "vim-minimal", Version: "2:7.4.629-6.el7.x86_64"},
						},
					},
				},
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2017-1000382",
						NamespaceName: "rhel:7",
						Description:   "DOCUMENTATION: It was found that vim applies the opened file read permissions to the swap file, overriding the process' umask. An attacker might search for vim swap files that were not deleted properly, in order to retrieve sensitive data.\n            STATEMENT: Red Hat Product Security has rated this issue as having Low security impact. This issue is not currently planned to be addressed in future updates. For additional information, refer to the Issue Severity Classification: https://access.redhat.com/security/updates/classification/.",
						Link:          "https://access.redhat.com/security/cve/CVE-2017-1000382",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
					},
				},
				AddedBy: "sha256:e20f387c7bf5a184eeef83f7e5626661f593ca05c788f377a01e2df62f613e44",
			},
		},
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:    "jackson-databind",
				Version: "2.7.6",
			},
		},
	},
	{
		// One of the images used for Red Hat Scanner Certification with a chown on jackson-databind that should not show up in the results.
		image:                   "quay.io/rhacs-eng/qa:sandbox-jenkins-agent-maven-35-rhel7-chown",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "Red Hat",
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "rh-maven35-log4j12",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "1.2.17-19.2.el7.noarch",
				AddedBy:       "sha256:4b4eac8c1d679c473379a42d37ec83b98bbafd8bb316200f53123f72d53bbb84",
			},
			{
				Name:          "rh-maven35-jackson-databind",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "2.7.6-2.10.el7.noarch",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2020:4173",
						NamespaceName: "rhel:7",
						Description:   "The jackson-databind package provides general data-binding functionality for Jackson, which works on top of Jackson core streaming API.\n\nSecurity Fix(es):\n\n* jackson-databind: Serialization gadgets in com.pastdev.httpcomponents.configuration.JndiConfiguration (CVE-2020-24750)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2020:4173",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         5.9,
									"Score":               8.1,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:2.7.6-2.11.el7",
					},
				},
				AddedBy: "sha256:4b4eac8c1d679c473379a42d37ec83b98bbafd8bb316200f53123f72d53bbb84",
				FixedBy: "2.7.6-2.12.el7",
			},
			{
				Name:          "vim-minimal",
				NamespaceName: "rhel:7",
				VersionFormat: "rpm",
				Version:       "2:7.4.629-6.el7.x86_64",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2017-1000382",
						NamespaceName: "rhel:7",
						Description:   "DOCUMENTATION: It was found that vim applies the opened file read permissions to the swap file, overriding the process' umask. An attacker might search for vim swap files that were not deleted properly, in order to retrieve sensitive data.\n            STATEMENT: Red Hat Product Security has rated this issue as having Low security impact. This issue is not currently planned to be addressed in future updates. For additional information, refer to the Issue Severity Classification: https://access.redhat.com/security/updates/classification/.",
						Link:          "https://access.redhat.com/security/cve/CVE-2017-1000382",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
					},
				},
				AddedBy: "sha256:e20f387c7bf5a184eeef83f7e5626661f593ca05c788f377a01e2df62f613e44",
			},
		},
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:    "jackson-databind",
				Version: "2.7.6",
			},
		},
	},
	{
		// One of the images used for Red Hat Scanner Certification.
		image:                   "quay.io/rhacs-eng/qa:sandbox-nodejs-10",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "Red Hat",
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "nodejs-full-i18n",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "1:10.21.0-3.module+el8.2.0+7071+d2377ea3.x86_64",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2021:0548",
						NamespaceName: "rhel:8",
						Description:   "Node.js is a software development platform for building fast and scalable network applications in the JavaScript programming language. \n\nThe following packages have been upgraded to a later upstream version: nodejs (10.23.1).\n\nSecurity Fix(es):\n\n* libuv: buffer overflow in realpath (CVE-2020-8252)\n\n* nodejs-npm-user-validate: improper input validation when validating user emails leads to ReDoS (CVE-2020-7754)\n\n* nodejs-y18n: prototype pollution vulnerability (CVE-2020-7774)\n\n* nodejs-ini: prototype pollution via malicious INI file (CVE-2020-7788)\n\n* nodejs-dot-prop: prototype pollution (CVE-2020-8116)\n\n* nodejs: use-after-free in the TLS implementation (CVE-2020-8265)\n\n* npm: sensitive information exposure through logs (CVE-2020-15095)\n\n* nodejs-ajv: prototype pollution via crafted JSON schema in ajv.validate function (CVE-2020-15366)\n\n* nodejs-yargs-parser: prototype pollution vulnerability (CVE-2020-7608)\n\n* nodejs: HTTP request smuggling via two copies of a header field in an http request (CVE-2020-8287)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2021:0548",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         5.9,
									"Score":               8.1,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "1:10.23.1-1.module+el8.3.0+9502+012d8a97",
					},
					{
						Name:          "RHSA-2021:0735",
						NamespaceName: "rhel:8",
						Description:   "Node.js is a software development platform for building fast and scalable network applications in the JavaScript programming language. \n\nThe following packages have been upgraded to a later upstream version: nodejs (10.24.0).\n\nSecurity Fix(es):\n\n* nodejs: HTTP2 'unknownProtocol' cause DoS by resource exhaustion (CVE-2021-22883)\n\n* nodejs: DNS rebinding in --inspect (CVE-2021-22884)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2021:0735",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "1:10.24.0-1.module+el8.3.0+10166+b07ac28e",
					},
				},
				AddedBy: "sha256:35ad9b4fba1fa6b00a6f266303348dc0cf9a7c341616e800c2738030c0f64167",
				FixedBy: "1:10.24.0-1.module+el8.3.0+10166+b07ac28e",
			},
			{
				Name:          "freetype",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "2.9.1-4.el8.x86_64",
				AddedBy:       "sha256:35ad9b4fba1fa6b00a6f266303348dc0cf9a7c341616e800c2738030c0f64167",
				FixedBy:       "2.9.1-10.el8_10",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2020:4952",
						NamespaceName: "rhel:8",
						Description:   "FreeType is a free, high-quality, portable font engine that can open and manage font files. FreeType loads, hints, and renders individual glyphs efficiently.\n\nSecurity Fix(es):\n\n* freetype: Heap-based buffer overflow due to integer truncation in Load_SBit_Png (CVE-2020-15999)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2020:4952",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         4.7,
									"Score":               8.6,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:2.9.1-4.el8_3.1",
					},
				},
			},
			{
				Name:          "libsolv",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "0.7.7-1.el8.x86_64",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2020:4508",
						NamespaceName: "rhel:8",
						Description:   "The libsolv packages provide a library for resolving package dependencies using a satisfiability algorithm.\n\nThe following packages have been upgraded to a later upstream version: libsolv (0.7.11). (BZ#1809106)\n\nSecurity Fix(es):\n\n* libsolv: out-of-bounds read in repodata_schema2id in repodata.c (CVE-2019-20387)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 8.3 Release Notes linked from the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2020:4508",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:0.7.11-1.el8",
					},
					{
						Name:          "RHSA-2021:4060",
						NamespaceName: "rhel:8",
						Description:   "The libsolv packages provide a library for resolving package dependencies using a satisfiability algorithm.\n\nSecurity Fix(es):\n\n* libsolv: heap-based buffer overflow in pool_installable() in src/repo.h (CVE-2021-33928)\n\n* libsolv: heap-based buffer overflow in pool_disabled_solvable() in src/repo.h (CVE-2021-33929)\n\n* libsolv: heap-based buffer overflow in pool_installable_whatprovides() in src/repo.h (CVE-2021-33930)\n\n* libsolv: heap-based buffer overflow in prune_to_recommended() in src/policy.c (CVE-2021-33938)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2021:4060",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:0.7.16-3.el8_4",
					},
					{
						Name:          "RHSA-2021:4408",
						NamespaceName: "rhel:8",
						Description:   "The libsolv packages provide a library for resolving package dependencies using a satisfiability algorithm.\n\nSecurity Fix(es):\n\n* libsolv: heap-based buffer overflow in testcase_read() in src/testcase.c (CVE-2021-3200)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the Red Hat Enterprise Linux 8.5 Release Notes linked from the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2021:4408",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         1.4,
									"Score":               3.3,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "0:0.7.19-1.el8",
					},
				},
				AddedBy: "sha256:ec1681b6a383e4ecedbeddd5abc596f3de835aed6db39a735f62395c8edbff30",
				FixedBy: "0.7.19-1.el8",
			},
		},
	},
	{
		image:           "registry.redhat.io/openshift3/logging-elasticsearch",
		registry:        "https://registry.redhat.io",
		username:        os.Getenv("REDHAT_USERNAME"),
		password:        os.Getenv("REDHAT_PASSWORD"),
		source:          "Red Hat",
		uncertifiedRHEL: true,
		namespace:       "centos:7",
	},
	{

		image:           "registry.redhat.io/openshift3/logging-elasticsearch:v3.10.175-1",
		registry:        "https://registry.redhat.io",
		username:        os.Getenv("REDHAT_USERNAME"),
		password:        os.Getenv("REDHAT_PASSWORD"),
		source:          "Red Hat",
		uncertifiedRHEL: true,
		namespace:       "centos:7",
	},
	{
		// Added to ensure no errors when analzying an image using the digest of a ManifestList
		image:           "registry.redhat.io/advanced-cluster-security/rhacs-collector-slim-rhel8:3.74.1@sha256:8e455c6f7ee571cc8c565b2f2b1ff712f05ade5cef0c34d528d2955253469992",
		registry:        "https://registry.redhat.io",
		username:        os.Getenv("REDHAT_USERNAME"),
		password:        os.Getenv("REDHAT_PASSWORD"),
		uncertifiedRHEL: false,
		namespace:       "rhel:8",
	},
	{
		// Had an issue where Scanner claimed jq 6.1-r1 was vulnerable to
		// a CVE fixed in 1.6_rc1-r0. We do NOT expect this version of
		// jq to be vulnerable to this CVE (CVE-2016-4074).
		image:     "quay.io/rhacs-eng/qa:sandbox-alpine-jq-1.6-r1",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "alpine:v3.13",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "jq",
				NamespaceName: "alpine:v3.13",
				VersionFormat: "apk",
				Version:       "1.6-r1",
				AddedBy:       "sha256:51c25658727f8bc3a4ef7c039257e136d23995bfdcfdc52dfb24104b5dc64720",
			},
		},
	},
	// Verify digest-based scanning and also a v1 versioned image
	// This image result has two layers with the same digests, so it checks a duplicate layer case
	{
		// quay.io/rhacs-eng/qa:richxsl-rhel7-sha256-8f3aae325d2074d2dc328cb532d6e7aeb0c588e15ddf847347038fe0566364d6
		image:           "quay.io/rhacs-eng/qa@sha256:092233f7907ea86d4480a2b3fd82fb836f518b9bff48aa9a73463fab4af40f65",
		registry:        "https://quay.io",
		username:        os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:        os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:          "NVD",
		uncertifiedRHEL: true,
		namespace:       "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "fipscheck",
				NamespaceName: "centos:7",
				VersionFormat: "rpm",
				Version:       "1.4.1-5.el7",
				AddedBy:       "sha256:17b2a618d73663dfbfc53ad5b0d74894ce659b6685d12301e13d2cebfa454b39",
			},
		},
	},
	{
		image:                   "quay.io/dougtidwell/open-adventure@sha256:564c8dde1931f337a7bc8925f94cb594d9c81a5ee9eacc5ec5590f1e60e94b6a",
		registry:                "https://quay.io",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "p11-kit",
				NamespaceName: "centos:7",
				VersionFormat: "rpm",
				Version:       "0.23.5-3.el7",
				AddedBy:       "sha256:f9ce27a295e879233c8fbbf9ab67944a10e1ce80da69e46f87c583082a1ff3bb",
			},
		},
	},
	{
		image:                    "quay.io/rhacs-eng/qa:alpine-3.13.0",
		registry:                 "https://quay.io",
		username:                 os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                 os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                   "NVD",
		onlyCheckSpecifiedVulns:  true,
		namespace:                "alpine:v3.13",
		checkProvidedExecutables: true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.13",
				VersionFormat: "apk",
				Version:       "2.12.0-r4",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-30139",
						NamespaceName: "alpine:v3.13",
						Description:   "In Alpine Linux apk-tools before 2.12.5, the tarball parser allows a buffer overflow and crash.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2021-30139",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         2.9,
									"Score":               5.0,
									"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
								},
							},
						},
						FixedBy: "2.12.5-r0",
					},
					{
						Name:          "CVE-2021-36159",
						NamespaceName: "alpine:v3.13",
						Description:   "libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the '\\0' terminator one byte too late.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2021-36159",
						Severity:      "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.2,
									"Score":               9.1,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         4.9,
									"Score":               6.4,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:N/A:P",
								},
							},
						},
						FixedBy: "2.12.6-r0",
					},
				},
				AddedBy: "sha256:9c4afaba1fb00d8f884dad50e7fd333196cbb2e03734c5b34bbcbfc5e38a9387",
				FixedBy: "2.12.6-r0",
				Executables: []*v1.Executable{
					{
						Path: "/lib/libapk.so.3.12.0",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apk-tools", Version: "2.12.0-r4"},
							{Name: "musl", Version: "1.2.2_pre7-r0"},
							{Name: "openssl", Version: "1.1.1i-r0"},
							{Name: "zlib", Version: "1.2.11-r3"},
						},
					},
					{
						Path: "/sbin/apk",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apk-tools", Version: "2.12.0-r4"},
							{Name: "openssl", Version: "1.1.1i-r0"},
							{Name: "musl", Version: "1.2.2_pre7-r0"},
							{Name: "zlib", Version: "1.2.11-r3"},
						},
					},
				},
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.13",
				VersionFormat: "apk",
				Version:       "1.32.1-r0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-28831",
						NamespaceName: "alpine:v3.13",
						Description:   "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2021-28831",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         2.9,
									"Score":               5.0,
									"Vectors":             "AV:N/AC:L/Au:N/C:N/I:N/A:P",
								},
							},
						},
						FixedBy: "1.32.1-r4",
					},
				},
				AddedBy: "sha256:9c4afaba1fb00d8f884dad50e7fd333196cbb2e03734c5b34bbcbfc5e38a9387",
				FixedBy: "1.32.1-r9",
				Executables: []*v1.Executable{
					{
						Path: "/usr/bin/ssl_client",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "busybox", Version: "1.32.1-r0"},
							{Name: "libtls-standalone", Version: "2.9.1-r1"},
							{Name: "musl", Version: "1.2.2_pre7-r0"},
							{Name: "openssl", Version: "1.1.1i-r0"},
						},
					},
					{
						Path: "/etc/network/if-up.d/dad",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "busybox", Version: "1.32.1-r0"},
						},
					},
					{
						Path: "/usr/share/udhcpc/default.script",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "busybox", Version: "1.32.1-r0"},
						},
					},
					{
						Path: "/bin/busybox",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "busybox", Version: "1.32.1-r0"},
							{Name: "musl", Version: "1.2.2_pre7-r0"},
						},
					},
				},
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.14.0",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.14",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.14",
				VersionFormat: "apk",
				Version:       "2.12.5-r1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-36159",
						NamespaceName: "alpine:v3.14",
						Description:   "libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the '\\0' terminator one byte too late.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2021-36159",
						Severity:      "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.2,
									"Score":               9.1,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         4.9,
									"Score":               6.4,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:N/A:P",
								},
							},
						},
						FixedBy: "2.12.6-r0",
					},
				},
				AddedBy: "sha256:27d926d71d0bbab9c30ef1caf3f631514971f7c7c9435f6ac7967ea0d1705e22",
				FixedBy: "2.12.6-r0",
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.14",
				VersionFormat: "apk",
				Version:       "1.33.1-r2",
				AddedBy:       "sha256:27d926d71d0bbab9c30ef1caf3f631514971f7c7c9435f6ac7967ea0d1705e22",
				FixedBy:       "1.33.1-r7",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.15.0",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.15",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.15",
				VersionFormat: "apk",
				Version:       "2.12.7-r3",
				AddedBy:       "sha256:f4a33864689e6fb2f052728abdf9e2ca75d28ee36cfafe0bda5b98efdea5772d",
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.15",
				VersionFormat: "apk",
				Version:       "1.34.1-r3",
				AddedBy:       "sha256:f4a33864689e6fb2f052728abdf9e2ca75d28ee36cfafe0bda5b98efdea5772d",
				FixedBy:       "1.34.1-r5",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.16.0",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.16",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.16",
				VersionFormat: "apk",
				Version:       "2.12.9-r3",
				AddedBy:       "sha256:2408cc74d12b6cd092bb8b516ba7d5e290f485d3eb9672efc00f0583730179e8",
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.16",
				VersionFormat: "apk",
				Version:       "1.35.0-r13",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2022-30065",
						NamespaceName: "alpine:v3.16",
						Description:   "A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2022-30065",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         5.9,
									"Score":               7.8,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 8.6,
									"ImpactScore":         6.4,
									"Score":               6.8,
									"Vectors":             "AV:N/AC:M/Au:N/C:P/I:P/A:P",
								},
							},
						},
						FixedBy: "1.35.0-r15",
					},
				},
				AddedBy: "sha256:2408cc74d12b6cd092bb8b516ba7d5e290f485d3eb9672efc00f0583730179e8",
				FixedBy: "1.35.0-r18",
			},
			{
				Name:          "openssl",
				NamespaceName: "alpine:v3.16",
				VersionFormat: "apk",
				Version:       "1.1.1o-r0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2022-2097",
						NamespaceName: "alpine:v3.16",
						Description:   "AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the special case of \"in place\" encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p).",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2022-2097",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         1.4,
									"Score":               5.3,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 10.0,
									"ImpactScore":         2.9,
									"Score":               5.0,
									"Vectors":             "AV:N/AC:L/Au:N/C:P/I:N/A:N",
								},
							},
						},
						FixedBy: "1.1.1q-r0",
					},
				},
				AddedBy: "sha256:2408cc74d12b6cd092bb8b516ba7d5e290f485d3eb9672efc00f0583730179e8",
				FixedBy: "1.1.1w-r1",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.17.0",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.17",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.17",
				VersionFormat: "apk",
				Version:       "2.12.10-r1",
				AddedBy:       "sha256:2815b02d45841c8d883e7b46b390e60fdfed11a471cccc85254595147e8e4588",
			},
		},
	},
	{
		image:    "quay.io/rhacs-eng/qa:debian-package-removal",
		registry: "https://quay.io",
		username: os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password: os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:   "NVD",
		// Ensure we find the executable files for packages added in a layer lower than the latest
		// package DB version. The relevant *.list file will only exist in the layer the package is added
		// so the layer with the latest packages DB will not have the *.list file for these packages.
		checkProvidedExecutables: true,
		namespace:                "debian:11",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "dash",
				NamespaceName: "debian:11",
				VersionFormat: "dpkg",
				Version:       "0.5.11+git20200708+dd9ef66-5",
				Executables: []*v1.Executable{
					{
						Path: "/bin/dash",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "dash", Version: "0.5.11+git20200708+dd9ef66-5"},
							{Name: "glibc", Version: "2.31-13"},
						},
					},
				},
				AddedBy: "sha256:4c25b3090c2685271afcffc2a4db73f15ab11a0124bfcde6085c934a4e6f4a51",
			},
			{
				Name:          "diffutils",
				NamespaceName: "debian:11",
				VersionFormat: "dpkg",
				Version:       "1:3.7-5",
				Executables: []*v1.Executable{
					{
						Path: "/usr/bin/cmp",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "diffutils", Version: "1:3.7-5"},
							{Name: "glibc", Version: "2.31-13"},
						},
					},
					{
						Path: "/usr/bin/diff",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "diffutils", Version: "1:3.7-5"},
							{Name: "glibc", Version: "2.31-13"},
						},
					},
					{
						Path: "/usr/bin/diff3",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "diffutils", Version: "1:3.7-5"},
							{Name: "glibc", Version: "2.31-13"},
						},
					},
					{
						Path: "/usr/bin/sdiff",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "diffutils", Version: "1:3.7-5"},
							{Name: "glibc", Version: "2.31-13"},
						},
					},
				},
				AddedBy: "sha256:4c25b3090c2685271afcffc2a4db73f15ab11a0124bfcde6085c934a4e6f4a51",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:anchore-anchore-engine-v0.9.4",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "rhel:8",
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:    "netaddr",
				Version: "0.8.0",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:elastic-logstash-7.13.3",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.9.1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2020-9488",
						Description: "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-9488",
						Severity:    "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         1.4,
									"Score":               3.7,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 8.6,
									"ImpactScore":         2.9,
									"Score":               4.3,
									"Vectors":             "AV:N/AC:M/Au:N/C:P/I:N/A:N",
								},
							},
						},
						FixedBy: "2.12.3",
					},
					{
						Name:        "CVE-2021-44228",
						Description: "In Apache Log4j2 versions up to and including 2.14.1 (excluding security release 2.12.2), the JNDI features used in configurations, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         6.0,
									"Score":               10.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.12.2",
					},
					{
						Name:        "CVE-2021-44832",
						Description: "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 0.7,
									"ImpactScore":         5.9,
									"Score":               6.6,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 6.8,
									"ImpactScore":         10.0,
									"Score":               8.5,
									"Vectors":             "AV:N/AC:M/Au:S/C:C/I:C/A:C",
								},
							},
						},
						FixedBy: "2.12.4",
					},
					{
						Name:        "CVE-2021-45046",
						Description: "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern, resulting in an information leak and remote code execution in some environments and local code execution in all environments; remote code execution has been demonstrated on macOS but no other tested environments.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         6.0,
									"Score":               9.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.12.2",
					},
					{
						Name:        "CVE-2021-45105",
						Description: "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         3.6,
									"Score":               5.9,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.12.3",
					},
				},
				AddedBy:  "sha256:477d0b4ccc14566aec80c3360aba6c84208c9d337727434c3914bd87b023dab3",
				Location: "usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-tcp-6.0.10-java/vendor/jar-dependencies/org/logstash/inputs/logstash-input-tcp/6.0.10/logstash-input-tcp-6.0.10.jar:log4j-core",
				FixedBy:  "2.12.4",
			},
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.14.0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2021-44228",
						Description: "In Apache Log4j2 versions up to and including 2.14.1 (excluding security release 2.12.2), the JNDI features used in configurations, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         6.0,
									"Score":               10.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.15.0",
					},
					{
						Name:        "CVE-2021-44832",
						Description: "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 0.7,
									"ImpactScore":         5.9,
									"Score":               6.6,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 6.8,
									"ImpactScore":         10.0,
									"Score":               8.5,
									"Vectors":             "AV:N/AC:M/Au:S/C:C/I:C/A:C",
								},
							},
						},
						FixedBy: "2.17.1",
					},
					{
						Name:        "CVE-2021-45046",
						Description: "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern, resulting in an information leak and remote code execution in some environments and local code execution in all environments; remote code execution has been demonstrated on macOS but no other tested environments.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         6.0,
									"Score":               9.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.16.0",
					},
					{
						Name:        "CVE-2021-45105",
						Description: "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         3.6,
									"Score":               5.9,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.17.0",
					},
				},
				AddedBy:  "sha256:477d0b4ccc14566aec80c3360aba6c84208c9d337727434c3914bd87b023dab3",
				Location: "usr/share/logstash/logstash-core/lib/jars/log4j-core-2.14.0.jar",
				FixedBy:  "2.17.1",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:sandbox-log4j-2-12-2",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "ubuntu:20.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.12.2",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2020-9488",
						Description: "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-9488",
						Severity:    "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         1.4,
									"Score":               3.7,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 8.6,
									"ImpactScore":         2.9,
									"Score":               4.3,
									"Vectors":             "AV:N/AC:M/Au:N/C:P/I:N/A:N",
								},
							},
						},
						FixedBy: "2.12.3",
					},
					{
						Name:        "CVE-2021-44832",
						Description: "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 0.7,
									"ImpactScore":         5.9,
									"Score":               6.6,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 6.8,
									"ImpactScore":         10.0,
									"Score":               8.5,
									"Vectors":             "AV:N/AC:M/Au:S/C:C/I:C/A:C",
								},
							},
						},
						FixedBy: "2.12.4",
					},
					{
						Name:        "CVE-2021-45105",
						Description: "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:    "Moderate",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         3.6,
									"Score":               5.9,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "2.12.3",
					},
				},
				AddedBy:  "sha256:d84ba7ea7803fa43fca06730523d264b31c562968cfd7020f0584f5ec1b26225",
				Location: "log4j-core-2.12.2.jar",
				FixedBy:  "2.12.4",
			},
		},
	},
	{
		image:     "quay.io/rhacs-eng/qa:busybox-1.35.0",
		registry:  "https://quay.io",
		username:  os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:  os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:    "NVD",
		namespace: "busybox:1.35.0",
	},
	{
		image:                   "quay.io/rhacs-eng/qa:sandbox-springboot-2.6.5",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		source:                  "NVD",
		namespace:               "alpine:v3.15",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "spring-webmvc",
				VersionFormat: "JavaSourceType",
				Version:       "5.3.17",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2022-22965",
						Description: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "5.3.18",
					},
				},
				AddedBy:  "sha256:bb57a75650ced8dd9ff54ca55ab34a150a7cb7b68258064056e65e0b2a9c3320",
				Location: "app/demo-0.0.1-SNAPSHOT.war:WEB-INF/lib/spring-webmvc-5.3.17.jar",
				FixedBy:  "5.3.18",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:sandbox-springboot-2.6.5-flux",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		source:                  "NVD",
		namespace:               "alpine:v3.15",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "spring-webflux",
				VersionFormat: "JavaSourceType",
				Version:       "5.3.17",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2022-22965",
						Description: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "5.3.18",
					},
				},
				AddedBy:  "sha256:f7edbdbbb0752d6ec06c7098cc966e7b36edf216a72c4d8c074ecf0d3a363b85",
				Location: "app/demo-0.0.1-SNAPSHOT.war:WEB-INF/lib/spring-webflux-5.3.17.jar",
				FixedBy:  "5.3.18",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:sandbox-springboot-web-cloud-function-2.6.6",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		source:                  "NVD",
		namespace:               "alpine:v3.15",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "spring-cloud-function-core",
				VersionFormat: "JavaSourceType",
				Version:       "3.2.2",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2022-22963",
						Description: "In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
						Severity:    "Critical",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
							},
						},
						FixedBy: "3.2.3",
					},
				},
				AddedBy:  "sha256:f26cc7bc44e4f9b8969a0a95040d484ab301b3e56d1fb1eda8a79bf7e089f24e",
				Location: "app/demo-0.0.1-SNAPSHOT.war:WEB-INF/lib/spring-cloud-function-core-3.2.2.jar",
				FixedBy:  "3.2.3",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-22.04-sha256-cd3d86f1fb368c6a53659d467560010ab9e0695528127ea336fe32f68f7ba09f",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:22.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "adduser",
				NamespaceName: "ubuntu:22.04",
				VersionFormat: "dpkg",
				Version:       "3.118ubuntu5",
				AddedBy:       "sha256:a0c79b13a593669e6152d94cfd64931dfe9fc897bc6507dfb4ae7fe57cd6e7ae",
			},
			{
				Name:          "apt",
				NamespaceName: "ubuntu:22.04",
				VersionFormat: "dpkg",
				Version:       "2.4.5",
				AddedBy:       "sha256:a0c79b13a593669e6152d94cfd64931dfe9fc897bc6507dfb4ae7fe57cd6e7ae",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-22.10-sha256-4f9ec2c0aa321966bfe625bc485aa1d6e96549679cfdf98bb404dfcb8e141a7f",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:22.10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "adduser",
				NamespaceName: "ubuntu:22.10",
				VersionFormat: "dpkg",
				Version:       "3.121ubuntu1",
				AddedBy:       "sha256:bcd446fbf8a137bbf135b63332ebcd0c3e9880060bc5b41962fbbb07e94062b7",
			},
			{
				Name:          "apt",
				NamespaceName: "ubuntu:22.10",
				VersionFormat: "dpkg",
				Version:       "2.5.3",
				AddedBy:       "sha256:bcd446fbf8a137bbf135b63332ebcd0c3e9880060bc5b41962fbbb07e94062b7",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ansibleplaybookbundle--gluster-s3object-apb--481960439934084fb041431f27cb98b89666e1a0daaeb2078bcbe1209790368c",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "Red Hat",
		onlyCheckSpecifiedVulns: true,
		namespace:               "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "ncurses-base",
				NamespaceName: "centos:7",
				VersionFormat: "rpm",
				Version:       "5.9-14.20130511.el7_4",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2017-10684",
						NamespaceName: "centos:7",
						Description:   "DOCUMENTATION: The MITRE CVE dictionary describes this issue as: In ncurses 6.0, there is a stack-based buffer overflow in the fmt_entry function. A crafted input will lead to a remote arbitrary code execution attack.              STATEMENT: Red Hat Product Security has rated this issue as having Moderate security impact. This issue is not currently planned to be addressed in future updates. For additional information, refer to the Issue Severity Classification: https://access.redhat.com/security/updates/classification/.",
						Link:          "https://access.redhat.com/security/cve/CVE-2017-10684",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.0,
									"ImpactScore":         4.2,
									"Score":               5.3,
									"Vectors":             "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H",
								},
							},
						},
					},
					{
						Name:          "CVE-2017-10685",
						NamespaceName: "centos:7",
						Description:   "DOCUMENTATION: The MITRE CVE dictionary describes this issue as: In ncurses 6.0, there is a format string vulnerability in the fmt_entry function. A crafted input will lead to a remote arbitrary code execution attack.              STATEMENT: Red Hat considers this issue as a duplicate of CVE-2017-10684.",
						Link:          "https://access.redhat.com/security/cve/CVE-2017-10685",
						Severity:      "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.5,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
								},
							},
						},
					},
				},
				AddedBy: "sha256:7dc0dca2b1516961d6b3200564049db0a6e0410b370bb2189e2efae0d368616f",
			},
		},
	},
	{
		requiredFeatureFlag:     features.RHEL9Scanning,
		image:                   "ubi9/ubi:9.0.0-1576@sha256:f22a438f4967419bd477c648d25ed0627f54b81931d0143dc45801c8356bd379",
		namespace:               "rhel:9",
		onlyCheckSpecifiedVulns: true,
		registry:                "https://registry.access.redhat.com",
		source:                  "Red Hat",
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:     "urllib3",
				Version:  "9.0-2.17",
				Location: "usr/lib/python3.9/site-packages/urllib3-1.26.5-py3.9.egg-info/PKG-INFO",
			},
		},
		expectedFeatures: []apiV1.Feature{
			{
				AddedBy:       "sha256:2412e60e610160d090f7e974a208c6ffd26b2d530361b7c9aa8967e160ac7996",
				Name:          "openssl",
				NamespaceName: "rhel:9",
				Version:       "1:3.0.1-23.el9_0.x86_64",
				VersionFormat: "rpm",
				FixedBy:       "1:3.2.2-6.el9_5.1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2022:7288",
						NamespaceName: "rhel:9",
						Description: `OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, as well as a full strength general purpose cryptography library.

Security Fix(es):

* OpenSSL: X.509 Email Address Buffer Overflow (CVE-2022-3602)

* OpenSSL: X.509 Email Address Variable Length Buffer Overflow (CVE-2022-3786)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.`,
						Link:     "https://access.redhat.com/errata/RHSA-2022:7288",
						Severity: "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
						FixedBy: "1:3.0.1-43.el9_0",
					},
				},
			},
			{
				AddedBy:       "sha256:2412e60e610160d090f7e974a208c6ffd26b2d530361b7c9aa8967e160ac7996",
				Name:          "openssl-libs",
				NamespaceName: "rhel:9",
				Version:       "1:3.0.1-23.el9_0.x86_64",
				VersionFormat: "rpm",
				FixedBy:       "1:3.2.2-6.el9_5.1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2022:7288",
						NamespaceName: "rhel:9",
						Description: `OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, as well as a full strength general purpose cryptography library.

Security Fix(es):

* OpenSSL: X.509 Email Address Buffer Overflow (CVE-2022-3602)

* OpenSSL: X.509 Email Address Variable Length Buffer Overflow (CVE-2022-3786)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.`,
						Link:     "https://access.redhat.com/errata/RHSA-2022:7288",
						Severity: "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
						FixedBy: "1:3.0.1-43.el9_0",
					},
				},
			},
			{
				AddedBy:       "sha256:2412e60e610160d090f7e974a208c6ffd26b2d530361b7c9aa8967e160ac7996",
				Name:          "python3-urllib3",
				NamespaceName: "rhel:9",
				Version:       "1.26.5-3.el9.noarch",
				VersionFormat: "rpm",
				FixedBy:       "1.26.5-5.el9_4.1",
			},
			{
				AddedBy:       "sha256:2412e60e610160d090f7e974a208c6ffd26b2d530361b7c9aa8967e160ac7996",
				FixedBy:       "2:8.2.2637-22.el9_6.1",
				Name:          "vim-minimal",
				NamespaceName: "rhel:9",
				Version:       "2:8.2.2637-16.el9_0.2.x86_64",
				VersionFormat: "rpm",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2022:5942",
						NamespaceName: "rhel:9",
						Description: `Vim (Vi IMproved) is an updated and improved version of the vi editor.

Security Fix(es):

* vim: Out-of-bounds Write (CVE-2022-1785)

* vim: out-of-bounds write in vim_regsub_both() in regexp.c (CVE-2022-1897)

* vim: buffer over-read in utf_ptr2char() in mbyte.c (CVE-2022-1927)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.`,
						Link:     "https://access.redhat.com/errata/RHSA-2022:5942",
						Severity: "Moderate",
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
									"ImpactScore":         5.9,
									"Score":               7.8,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
								},
							},
						},
						FixedBy: "2:8.2.2637-16.el9_0.3",
					},
				},
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:sandbox-dotnet-60-runtime-6.0-15.20220620151726",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "Red Hat",
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "aspnetcore-runtime-6.0",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "6.0.6-1.el8_6.x86_64",
				FixedBy:       "6.0.35-1.el8_10",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHBA-2022:5747",
						NamespaceName: "rhel:8",
						Description: `.NET Core is a managed-software framework. It implements a subset of the .NET
framework APIs and several new APIs, and it includes a CLR implementation.

Bug Fix(es) and Enhancement(s):

* Update .NET 6.0 to SDK 6.0.107 and Runtime 6.0.7 [rhel-8.6.0.z] (BZ#2105397)`,
						Link:     "https://access.redhat.com/errata/RHBA-2022:5747",
						Severity: "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.8,
									"ImpactScore":         5.8,
									"Score":               9.3,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
								},
							},
						},
						FixedBy: "0:6.0.7-1.el8_6",
					},
				},
				AddedBy: "sha256:16e1dc59de605089610e3be2c77f3cde5eed99b523a0d7a3e3a2f65fa7c60723",
			},
			{
				Name:          "dotnet-runtime-6.0",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "6.0.6-1.el8_6.x86_64",
				FixedBy:       "6.0.35-1.el8_10",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHBA-2022:5747",
						NamespaceName: "rhel:8",
						Description: `.NET Core is a managed-software framework. It implements a subset of the .NET
framework APIs and several new APIs, and it includes a CLR implementation.

Bug Fix(es) and Enhancement(s):

* Update .NET 6.0 to SDK 6.0.107 and Runtime 6.0.7 [rhel-8.6.0.z] (BZ#2105397)`,
						Link:     "https://access.redhat.com/errata/RHBA-2022:5747",
						Severity: "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.8,
									"ImpactScore":         5.8,
									"Score":               9.3,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
								},
							},
						},
						FixedBy: "0:6.0.7-1.el8_6",
					},
				},
				AddedBy: "sha256:16e1dc59de605089610e3be2c77f3cde5eed99b523a0d7a3e3a2f65fa7c60723",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:spring-CVE-2022-22978",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "spring-security-web",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "5.5.5",
				Location:      "application/app.jar:BOOT-INF/lib/spring-security-web-5.5.5.jar",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name: "CVE-2022-22978",
						Description: `In Spring Security versions 5.5.6 and 5.6.3 and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers.

Applications using RegexRequestMatcher with '.' in the regular expression are possibly vulnerable to an authorization bypass.`,
						Link:     "https://nvd.nist.gov/vuln/detail/CVE-2022-22978",
						Severity: "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         4.2,
									"Score":               8.2,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
								},
							},
						},
						FixedBy: "5.5.7",
					},
				},
				FixedBy: "5.5.7",
				AddedBy: "sha256:5b6e3ce9721946e142ba43e488385ee4d323204a6052e0f20352d89ac00cafa2",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-22.04-openssl",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:22.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "openssl",
				NamespaceName: "ubuntu:22.04",
				VersionFormat: "dpkg",
				Version:       "3.0.2-0ubuntu1.6",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2022-3602",
						NamespaceName: "ubuntu:22.04",
						Description:   "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).",
						Link:          "https://ubuntu.com/security/CVE-2022-3602",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
						FixedBy: "3.0.2-0ubuntu1.7",
					},
					{
						Name:          "CVE-2022-3786",
						NamespaceName: "ubuntu:22.04",
						Description:   "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.",
						Link:          "https://ubuntu.com/security/CVE-2022-3786",
						Severity:      "Important",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
						FixedBy: "3.0.2-0ubuntu1.7",
					},
				},
				FixedBy: "3.0.2-0ubuntu1.18",
				// This image installs the openssl package in the second layer;
				// however, the first layer already installed libssl3 whose source package is openssl.
				// Therefore, we claim openssl was installed in the first layer.
				AddedBy: "sha256:301a8b74f71f85f3a31e9c7e7fedd5b001ead5bcf895bc2911c1d260e06bd987",
			},
		},
	},
	// This image is not affected by CVE-2022-3602 nor CVE-2022-3786, as it has a fixed version of OpenSSL.
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-22.10-openssl",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:22.10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "openssl",
				NamespaceName: "ubuntu:22.10",
				VersionFormat: "dpkg",
				Version:       "3.0.5-2ubuntu2",
				FixedBy:       "3.0.5-2ubuntu2.3",
				AddedBy:       "sha256:2b441754735ea7decb684ef19d54115fc309c270fe7b87ed36aa3773ce50b78b",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ose-jenkins",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "Red Hat",
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "jenkins-2-plugins",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "4.10.1650890594-1.el8.noarch",
				AddedBy:       "sha256:3fa3f612bdcb92746bf76be1b9c9e1c1c80de777aedaf48b7068f4a129ded3c2",
				FixedBy:       "4.10.1685679861-1.el8",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-26291",
						NamespaceName: "rhel:8",
						Description: `DOCUMENTATION: A flaw was found in maven. Repositories that are defined in a dependency’s Project Object Model (pom), which may be unknown to users, are used by default resulting in potential risk if a malicious actor takes over that repository or is able to insert themselves into a position to pretend to be that repository. The highest threat from this vulnerability is to data confidentiality and integrity. 
            
            MITIGATION: To avoid possible man-in-the-middle related attacks with this flaw, ensure any linked repositories in maven POMs use https and not http.`,
						Link:     "https://access.redhat.com/security/cve/CVE-2021-26291",
						Severity: "Moderate",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         5.2,
									"Score":               7.4,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
								},
							},
						},
					},
					{
						Name:          "RHSA-2022:6531",
						NamespaceName: "rhel:8",
						Description: `Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or private
cloud deployments.

This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.10.33. See the following advisory for the container images for this release:

https://access.redhat.com/errata/RHBA-2022:6532

Security Fix(es):

* jenkins-plugin: Arbitrary file write vulnerability in Pipeline Input Step
Plugin (CVE-2022-34177)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s)
listed in the References section.

All OpenShift Container Platform 4.10 users are advised to upgrade to these updated packages and images when they are available in the appropriate release channel. To check for available updates, use the OpenShift Console or the CLI oc command. Instructions for upgrading a cluster are available at https://docs.openshift.com/container-platform/4.10/updating/updating-cluster-cli.html`,
						Link:     "https://access.redhat.com/errata/RHSA-2022:6531",
						Severity: "Important",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
								},
							},
						},
						FixedBy: "0:4.10.1663147786-1.el8",
					},
				},
			},
		},
	},
	{
		// OCI v1 Image Index manifest type.
		image:                   "gcr.io/distroless/static-debian11@sha256:a01d47d4036cae5a67a9619e3d06fa14a6811a2247b4da72b4233ece4efebd57",
		registry:                "https://gcr.io",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "debian:11",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "tzdata",
				NamespaceName: "debian:11",
				VersionFormat: "dpkg",
				Version:       "2021a-1+deb11u9",
				AddedBy:       "sha256:fff4e558ad3a0d44f9ec0bf32771df4a102c6d93fce253dd3eb6657865b78a49",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:drools-CVE-2021-41411",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		namespace:               "rhel:8",
		onlyCheckSpecifiedVulns: true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "drools",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "6.4.0.final",
				Location:      "org.drools.drools-core-6.4.0.Final.jar:drools-core",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2021-41411",
						Description: "drools <=7.59.x is affected by an XML External Entity (XXE) vulnerability in KieModuleMarshaller.java. The Validator class is not used correctly, resulting in the XXE injection vulnerability.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-41411",
						Severity:    "Critical",
						FixedBy:     "7.60.0.Final",
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
							},
						},
					},
				},
				FixedBy: "7.60.0.Final",
				AddedBy: "sha256:3078c14ffbc62cd9a56f8951d08d6b55a45394fbb5a0aa8f9eca1b1472e3f21d",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:tomcat-9.0.59",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		namespace:               "alpine:v3.15",
		onlyCheckSpecifiedVulns: true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "tomcat",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "9.0.59",
				FixedBy:       "9.0.108",
				Location:      "tomcat-embed-core-9.0.59.jar",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2022-29885",
						Description: "The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and 8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly stated it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the EncryptInterceptor does provide confidentiality and integrity protection, it does not protect against all risks associated with running over any untrusted network, particularly DoS risks.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2022-29885",
						Severity:    "Important",
						FixedBy:     "", // This should be fixed, but NVD did not set this properly.
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
							},
						},
					},
					{
						Name:        "CVE-2023-28708",
						Description: "When using the RemoteIpFilter with requests received from a    reverse proxy via HTTP that include the X-Forwarded-Proto    header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2, 10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 did not\u00a0include the secure attribute. This could result in the user agent\u00a0transmitting the session cookie over an insecure channel.\n\nOlder, EOL versions may also be affected.",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2023-28708",
						Severity:    "Moderate",
						FixedBy:     "9.0.72",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.8,
									"ImpactScore":         1.4,
									"Score":               4.3,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
								},
							},
						},
					},
				},
				AddedBy: "sha256:97444f2bde8fa4fdfb6ec630b24fbdf95017c6813f4b5e68e64a4280b276eff2",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.18.3",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.18",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.18",
				VersionFormat: "apk",
				Version:       "2.14.0-r2",
				AddedBy:       "sha256:97d7b294855ea22919bd873ce14c0bde0ba6702a2324133153d589153d96bd93",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:debian-12.0",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "debian:12",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "base-files",
				NamespaceName: "debian:12",
				VersionFormat: "dpkg",
				Version:       "12.4",
				AddedBy:       "sha256:d52e4f012db158bb7c0fe215b98af1facaddcbaee530efd69b1bae07d597b711",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-23.04",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:23.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "base-files",
				NamespaceName: "ubuntu:23.04",
				VersionFormat: "dpkg",
				Version:       "12.3ubuntu2",
				AddedBy:       "sha256:b631a20f124dbf4ef89945623fa5c94460561f9c7b119e17fd3c1a4bb50ced01",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-23.10",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:23.10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "base-files",
				NamespaceName: "ubuntu:23.10",
				VersionFormat: "dpkg",
				Version:       "13ubuntu1",
				AddedBy:       "sha256:316675922a661ce4c35389bdeea6e9ec8d4708e41f08671b586c7aaea469b2c1",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:nginx-1.25.0-alpine",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		namespace:               "alpine:v3.17",
		onlyCheckSpecifiedVulns: true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "libx11",
				NamespaceName: "alpine:v3.17",
				VersionFormat: "apk",
				Version:       "1.8.4-r0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2023-3138",
						NamespaceName: "alpine:v3.17",
						Description:   "A vulnerability was found in libX11. The security flaw occurs because the functions in src/InitExt.c in libX11 do not check that the values provided for the Request, Event, or Error IDs are within the bounds of the arrays that those functions write to, using those IDs as array indexes. They trust that they were called with values provided by an Xserver adhering to the bounds specified in the X11 protocol, as all X servers provided by X.Org do. As the protocol only specifies a single byte for these values, an out-of-bounds value provided by a malicious server (or a malicious proxy-in-the-middle) can only overwrite other portions of the Display structure and not write outside the bounds of the Display structure itself, possibly causing the client to crash with this memory corruption.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2023-3138",
						Severity:      "Important",
						FixedBy:       "1.8.4-r1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
				},
				FixedBy: "1.8.7-r0",
				AddedBy: "sha256:8ba39c19cf5d314e89905dfbfe4100fb747ecee0cba4a16104f4c3d904b22f21",
			},
			{
				Name:          "nghttp2",
				NamespaceName: "alpine:v3.17",
				VersionFormat: "apk",
				Version:       "1.51.0-r0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2023-35945",
						NamespaceName: "alpine:v3.17",
						Description:   "Envoy is a cloud-native high-performance edge/middle/service proxy. Envoy’s HTTP/2 codec may leak a header map and bookkeeping structures upon receiving `RST_STREAM` immediately followed by the `GOAWAY` frames from an upstream server. In nghttp2, cleanup of pending requests due to receipt of the `GOAWAY` frame skips de-allocation of the bookkeeping structure and pending compressed header. The error return [code path] is taken if connection is already marked for not sending more requests due to `GOAWAY` frame. The clean-up code is right after the return statement, causing memory leak. Denial of service through memory exhaustion. This vulnerability was patched in versions(s) 1.26.3, 1.25.8, 1.24.9, 1.23.11.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2023-35945",
						Severity:      "Important",
						FixedBy:       "1.51.0-r1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
				},
				FixedBy: "1.51.0-r2",
				AddedBy: "sha256:8ba39c19cf5d314e89905dfbfe4100fb747ecee0cba4a16104f4c3d904b22f21",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:sqlite-jdbc-CVE-2023-32697",
		registry:                "https://quay.io",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		source:                  "NVD",
		namespace:               "rhel:9",
		onlyCheckSpecifiedVulns: true,
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "sqlite-jdbc",
				VersionFormat: component.JavaSourceType.String(),
				Version:       "3.41.2.1",
				Location:      "sqlite-jdbc-3.41.2.1.jar",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:        "CVE-2023-32697",
						Description: "SQLite JDBC is a library for accessing and creating SQLite database files in Java. Sqlite-jdbc addresses a remote code execution vulnerability via JDBC URL. This issue impacting versions 3.6.14.1 through 3.41.2.1 and has been fixed in version 3.41.2.2.\n",
						Link:        "https://nvd.nist.gov/vuln/detail/CVE-2023-32697",
						Severity:    "Critical",
						FixedBy:     "3.41.2.2",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
							},
						},
					},
				},
				FixedBy: "3.41.2.2",
				AddedBy: "sha256:65801021513c110642748b4d5462a0e123f0b09077cda2844ef97b05135369a2",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-3.19.0",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.19",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "openssl",
				NamespaceName: "alpine:v3.19",
				VersionFormat: "apk",
				Version:       "3.1.4-r2",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2023-6129",
						NamespaceName: "alpine:v3.19",
						Description:   "Issue summary: The POLY1305 MAC (message authentication code) implementation\ncontains a bug that might corrupt the internal state of applications running\non PowerPC CPU based platforms if the CPU provides vector instructions.\n\nImpact summary: If an attacker can influence whether the POLY1305 MAC\nalgorithm is used, the application state might be corrupted with various\napplication dependent consequences.\n\nThe POLY1305 MAC (message authentication code) implementation in OpenSSL for\nPowerPC CPUs restores the contents of vector registers in a different order\nthan they are saved. Thus the contents of some of these vector registers\nare corrupted when returning to the caller. The vulnerable code is used only\non newer PowerPC processors supporting the PowerISA 2.07 instructions.\n\nThe consequences of this kind of internal application state corruption can\nbe various - from no consequences, if the calling application does not\ndepend on the contents of non-volatile XMM registers at all, to the worst\nconsequences, where the attacker could get complete control of the application\nprocess. However unless the compiler uses the vector registers for storing\npointers, the most likely consequence, if any, would be an incorrect result\nof some application dependent calculations or a crash leading to a denial of\nservice.\n\nThe POLY1305 MAC algorithm is most frequently used as part of the\nCHACHA20-POLY1305 AEAD (authenticated encryption with associated data)\nalgorithm. The most common usage of this AEAD cipher is with TLS protocol\nversions 1.2 and 1.3. If this cipher is enabled on the server a malicious\nclient can influence whether this AEAD cipher is used. This implies that\nTLS server applications using OpenSSL can be potentially impacted. However\nwe are currently not aware of any concrete application that would be affected\nby this issue therefore we consider this a Low severity security issue.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2023-6129",
						Severity:      "Moderate",
						FixedBy:       "3.1.4-r3",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         4.2,
									"Score":               6.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H",
								},
							},
						},
					},
				},
				AddedBy: "sha256:661ff4d9561e3fd050929ee5097067c34bafc523ee60f5294a37fd08056a73ca",
				FixedBy: "3.1.7-r0",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-24.04",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:24.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "base-files",
				NamespaceName: "ubuntu:24.04",
				VersionFormat: "dpkg",
				Version:       "13ubuntu10",
				AddedBy:       "sha256:8f5159575f7bbbce11277d1532c12d73076587ebb492562917370449a8c5e7fa",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:alpine-v3.20.0",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.20",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "openssl",
				NamespaceName: "alpine:v3.20",
				VersionFormat: "apk",
				Version:       "3.3.0-r2",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2024-6119",
						NamespaceName: "alpine:v3.20",
						Description:   "Issue summary: Applications performing certificate name checks (e.g., TLS\nclients checking server certificates) may attempt to read an invalid memory\naddress resulting in abnormal termination of the application process.\n\nImpact summary: Abnormal termination of an application can a cause a denial of\nservice.\n\nApplications performing certificate name checks (e.g., TLS clients checking\nserver certificates) may attempt to read an invalid memory address when\ncomparing the expected name with an `otherName` subject alternative name of an\nX.509 certificate. This may result in an exception that terminates the\napplication program.\n\nNote that basic certificate chain validation (signatures, dates, ...) is not\naffected, the denial of service can occur only when the application also\nspecifies an expected DNS name, Email address or IP address.\n\nTLS servers rarely solicit client certificates, and even when they do, they\ngenerally don't perform a name check against a reference identifier (expected\nidentity), but rather extract the presented identity after checking the\ncertificate chain.  So TLS servers are generally not affected and the severity\nof the issue is Moderate.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
						Link:          "https://www.cve.org/CVERecord?id=CVE-2024-6119",
						Severity:      "Important",
						FixedBy:       "3.3.2-r0",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
				},
				AddedBy: "sha256:d25f557d7f31bf7acfac935859b5153da41d13c41f2b468d16f729a5b883634f",
				FixedBy: "3.3.2-r0",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubi8-cups-vulns",
		registry:                "https://quay.io",
		source:                  "Red Hat",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "cups-filters",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "1.20.0-34.el8.x86_64",
				AddedBy:       "sha256:7a6d2526dba4ead4120381a83ce344db5959e947aab63fa3d1a3fae4f7986d62",
				FixedBy:       "1.20.0-35.el8_10",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2024:7463",
						NamespaceName: "rhel:8",
						Description:   "The cups-filters package contains back ends, filters, and other software that was once part of the core Common UNIX Printing System (CUPS) distribution but is now maintained independently. \n\nSecurity Fix(es):\n\n* cups-browsed: cups-browsed binds on UDP INADDR_ANY:631 trusting any packet from any source ()\n\n* cups-filters: libcupsfilters: `cfGetPrinterAttributes` API does not perform sanitization on returned IPP attributes (CVE-2024-47076)\n\n* cups: libppd: remote command injection via attacker controlled data in PPD file ()\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2024:7463",
						Severity:      "Important",
						FixedBy:       "0:1.20.0-35.el8_10",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         4.2,
									"Score":               8.2,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
								},
							},
						},
					},
				},
			},
			{
				Name:          "cups",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "1:2.2.6-60.el8_10.x86_64",
				AddedBy:       "sha256:7a6d2526dba4ead4120381a83ce344db5959e947aab63fa3d1a3fae4f7986d62",
				FixedBy:       "1:2.2.6-63.el8_10",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "RHSA-2025:0083",
						NamespaceName: "rhel:8",
						Description:   "The Common UNIX Printing System (CUPS) provides a portable printing layer for Linux, UNIX, and similar operating systems.\n\nSecurity Fix(es):\n\n* cups: libppd: remote command injection via attacker controlled data in PPD file (CVE-2024-47175)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
						Link:          "https://access.redhat.com/errata/RHSA-2025:0083",
						Severity:      "Low",
						FixedBy:       "1:2.2.6-62.el8_10",
						Metadata: map[string]interface{}{
							"Red Hat": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         5.5,
									"Score":               7.7,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:debian12-cups-vulns",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "debian:12",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "cups-filters",
				NamespaceName: "debian:12",
				VersionFormat: "dpkg",
				Version:       "1.28.17-3",
				AddedBy:       "sha256:8144b98fa7b4e7cfd356b0be733a31c453f04de4369fd76237d839db8215ed1c",
				FixedBy:       "1.28.17-3+deb12u1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2024-47076",
						NamespaceName: "debian:12",
						Description:   "CUPS is a standards-based, open-source printing system, and `libcupsfilters` contains the code of the filters of the former `cups-filters` package as library functions to be used for the data format conversion tasks needed in Printer Applications. The `cfGetPrinterAttributes5` function in `libcupsfilters` does not sanitize IPP attributes returned from an IPP server. When these IPP attributes are used, for instance, to generate a PPD file, this can lead to attacker controlled data to be provided to the rest of the CUPS system.",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2024-47076",
						Severity:      "Important",
						FixedBy:       "1.28.17-3+deb12u1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-09-27T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         4.0,
									"Score":               8.6,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N",
								},
							},
						},
					},
					{
						Name:          "CVE-2024-47176",
						NamespaceName: "debian:12",
						Description:   "CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL.  Due to the service binding to `*:631 ( INADDR_ANY )`, multiple bugs in `cups-browsed` can be exploited in sequence to introduce a malicious printer to the system. This chain of exploits ultimately enables an attacker to execute arbitrary commands remotely on the target machine without authentication when a print job is started. This poses a significant security risk over the network. Notably, this vulnerability is particularly concerning as it can be exploited from the public internet, potentially exposing a vast number of systems to remote attacks if their CUPS services are enabled.",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2024-47176",
						Severity:      "Important",
						FixedBy:       "1.28.17-3+deb12u1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-10-11T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         1.4,
									"Score":               5.3,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
								},
							},
						},
					},
					{
						Name:          "CVE-2024-47177",
						NamespaceName: "debian:12",
						Description:   "CUPS is a standards-based, open-source printing system, and cups-filters provides backends, filters, and other software for CUPS 2.x to use on non-Mac OS systems. Any value passed to `FoomaticRIPCommandLine` via a PPD file will be executed as a user controlled command. When combined with other logic bugs as described in CVE_2024-47176, this can lead to remote command execution.",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2024-47177",
						Severity:      "Important",
						FixedBy:       "",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-09-27T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         6.0,
									"Score":               9.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
							},
						},
					},
					{
						Name:          "CVE-2024-47850",
						NamespaceName: "debian:12",
						Description:   "CUPS cups-browsed before 2.5b1 will send an HTTP POST request to an arbitrary destination and port in response to a single IPP UDP packet requesting a printer to be added, a different vulnerability than CVE-2024-47176. (The request is meant to probe the new printer but can be used to create DDoS amplification attacks.)",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2024-47850",
						Severity:      "Important",
						FixedBy:       "",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-10-04T16:00Z",
								"LastModifiedDateTime": "2024-10-07T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
				},
			},
			{
				Name:          "cups",
				NamespaceName: "debian:12",
				VersionFormat: "dpkg",
				Version:       "2.4.2-3+deb12u7",
				AddedBy:       "sha256:8144b98fa7b4e7cfd356b0be733a31c453f04de4369fd76237d839db8215ed1c",
				FixedBy:       "2.4.2-3+deb12u8",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2024-47175",
						NamespaceName: "debian:12",
						Description:   "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
						Link:          "https://security-tracker.debian.org/tracker/CVE-2024-47175",
						Severity:      "Low",
						FixedBy:       "2.4.2-3+deb12u8",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-09-27T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu18.04-cups-vulns",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:18.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "cups",
				NamespaceName: "ubuntu:18.04",
				VersionFormat: "dpkg",
				Version:       "2.2.7-1ubuntu2.10",
				AddedBy:       "sha256:deb4f515230cd51956c71ab9bb67732b471bbe5905e96b9a76b934d4d2cceeb3",
				FixedBy:       "2.2.7-1ubuntu2.10+esm6",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2024-47175",
						NamespaceName: "ubuntu:18.04",
						Description:   "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
						Link:          "https://ubuntu.com/security/CVE-2024-47175",
						Severity:      "Moderate",
						FixedBy:       "2.2.7-1ubuntu2.10+esm6",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-10-02T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         5.9,
									"Score":               9.8,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								},
							},
						},
					},
				},
			},
			{
				Name:          "cups-filters",
				NamespaceName: "ubuntu:18.04",
				VersionFormat: "dpkg",
				Version:       "1.20.2-0ubuntu3.3",
				AddedBy:       "sha256:deb4f515230cd51956c71ab9bb67732b471bbe5905e96b9a76b934d4d2cceeb3",
				FixedBy:       "1.20.2-0ubuntu3.3+esm1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2024-47176",
						NamespaceName: "ubuntu:18.04",
						Description:   "Multiple bugs leading to info leak and remote code execution",
						Link:          "https://ubuntu.com/security/CVE-2024-47176",
						Severity:      "Moderate",
						FixedBy:       "1.20.2-0ubuntu3.3+esm1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-09-27T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
					{
						Name:          "CVE-2024-47177",
						NamespaceName: "ubuntu:18.04",
						Description:   "Command injection via FoomaticRIPCommandLine",
						Link:          "https://ubuntu.com/security/CVE-2024-47177",
						Severity:      "Moderate",
						FixedBy:       "",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-09-26T16:00Z",
								"LastModifiedDateTime": "2024-09-27T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 2.2,
									"ImpactScore":         6.0,
									"Score":               9.0,
									"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
								},
							},
						},
					},
					{
						Name:          "CVE-2024-47850",
						NamespaceName: "ubuntu:18.04",
						Description:   "CUPS cups-browsed before 2.5b1 will send an HTTP POST request to an arbitrary destination and port in response to a single IPP UDP packet requesting a printer to be added, a different vulnerability than CVE-2024-47176. (The request is meant to probe the new printer but can be used to create DDoS amplification attacks.)",
						Link:          "https://ubuntu.com/security/CVE-2024-47850",
						Severity:      "Moderate",
						FixedBy:       "1.20.2-0ubuntu3.3+esm1",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"PublishedDateTime":    "2024-10-04T16:00Z",
								"LastModifiedDateTime": "2024-10-09T16:00Z",
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 0.0,
									"ImpactScore":         0.0,
									"Score":               0.0,
									"Vectors":             "",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         3.6,
									"Score":               7.5,
									"Vectors":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:ubuntu-24.10",
		registry:                "https://quay.io",
		source:                  "NVD",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:24.10",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "base-files",
				NamespaceName: "ubuntu:24.10",
				VersionFormat: "dpkg",
				Version:       "13.3ubuntu6",
				AddedBy:       "sha256:9343428dd50e3bee43f9e7a0a2ecc8361a2db69756d40b20c42360457a1083af",
			},
		},
	},
	// START: Lineage Tests
	// The order of the next tests is important, the intent is to reproduce the conditions described in ROX-26604
	// in which differing parent layers were not properly handled leading to inaccuracies. These images share top
	// and bottom layers, middle layers differ.
	// Dockerfiles at: github.com/stackrox/stackrox/qa-tests-backend/test-images/lineage
	{
		image:                   "quay.io/rhacs-eng/qa:lineage-jdk-17.0.11",
		registry:                "https://quay.io",
		source:                  "Red Hat",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "java-17-openjdk-headless",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "1:17.0.11.0.9-2.el8.x86_64",
				FixedBy:       "1:17.0.17.0.10-1.el8",
				AddedBy:       "sha256:06c7a3d491f551a56296ccb9bee8a68c83776991e73a9005e8b5ebb533002097",
			},
		},
	},
	{
		image:                   "quay.io/rhacs-eng/qa:lineage-jdk-17.0.13",
		registry:                "https://quay.io",
		source:                  "Red Hat",
		username:                os.Getenv("QUAY_RHACS_ENG_RO_USERNAME"),
		password:                os.Getenv("QUAY_RHACS_ENG_RO_PASSWORD"),
		onlyCheckSpecifiedVulns: true,
		namespace:               "rhel:8",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "java-17-openjdk-headless",
				NamespaceName: "rhel:8",
				VersionFormat: "rpm",
				Version:       "1:17.0.13.0.11-3.el8.x86_64",
				FixedBy:       "1:17.0.17.0.10-1.el8",
				AddedBy:       "sha256:2f7b9495af5ddc85b0be7ca9411fddb54f37999ea73b03cbf1115dd0c5bd4f95",
			},
		},
	},
	// END: Lineage Tests
}
