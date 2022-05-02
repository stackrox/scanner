// +build e2e

package e2etests

import (
	"os"

	apiV1 "github.com/stackrox/scanner/api/v1"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/component"
)

type testCase struct {
	image              string
	registry           string
	username, password string
	source             string
	namespace          string
	expectedFeatures   []apiV1.Feature
	unexpectedFeatures []apiV1.Feature
	// This specifies that the features only need to contain at least the vulnerabilities specified
	onlyCheckSpecifiedVulns  bool
	uncertifiedRHEL          bool
	checkProvidedExecutables bool
}

var testCases = []testCase{
	{
		image:                    "ubuntu:16.04",
		registry:                 "https://registry-1.docker.io",
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
		image:     "docker.io/library/nginx:1.10",
		registry:  "https://registry-1.docker.io",
		source:    "NVD",
		namespace: "debian:8",
		expectedFeatures: []apiV1.Feature{
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
				AddedBy: "sha256:6d827a3ef358f4fa21ef8251f95492e667da826653fd43641cef5a877dc03a70",
			},
		},
	},
	{
		image:                    "docker.io/kaizheh/apache-struts2-cve-2017-5638:latest",
		registry:                 "https://registry-1.docker.io",
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
				AddedBy: "sha256:9f0706ba7422412cd468804fee456786f88bed94bf9aea6dde2a47f770d19d27",
				FixedBy: "1.0.9.8.6",
			},
		},
	},
	{
		image:     "docker.io/anchore/anchore-engine:v0.5.0",
		registry:  "https://registry-1.docker.io",
		source:    "Red Hat",
		namespace: "centos:7",
		// This image is older than June 2020, so we need to explicitly request for an uncertified scan.
		uncertifiedRHEL:          true,
		checkProvidedExecutables: true,
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
							{Name: "ncurses-libs", Version:  "5.9-14.20130511.el7_4"},
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
							{Name: "ncurses-libs", Version:  "5.9-14.20130511.el7_4"},
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
							{Name: "ncurses-libs", Version:  "5.9-14.20130511.el7_4"},
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
				AddedBy: "sha256:c8d67acdb2ffaebd638cf55a8fccc63693211060670aa7f0ea1d65b5d2c674dd",
			},
		},
	},
	{
		image:     "us.gcr.io/stackrox-ci/qa/apache/server:latest",
		registry:  "https://us.gcr.io",
		username:  "_json_key",
		password:  os.Getenv("GOOGLE_SA_CIRCLECI_SCANNER"),
		source:    "NVD",
		namespace: "ubuntu:14.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "cron",
				NamespaceName: "ubuntu:14.04",
				VersionFormat: "dpkg",
				Version:       "3.0pl1-124ubuntu2",
				AddedBy:       "sha256:bae382666908fd87a3a3646d7eb7176fa42226027d3256cac38ee0b79bdb0491",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2017-9525",
						NamespaceName: "ubuntu:14.04",
						Description:   "In the cron package through 3.0pl1-128 on Debian, and through 3.0pl1-128ubuntu2 on Ubuntu, the postinst maintainer script allows for group-crontab-to-root privilege escalation via symlink attacks against unsafe usage of the chown and chmod programs.",
						Link:          "https://ubuntu.com/security/CVE-2017-9525",
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
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
								},
								"LastModifiedDateTime": "2019-03-21T23:29Z",
								"PublishedDateTime":    "2017-06-09T16:29Z",
							},
						},
					},
					{
						Name:          "CVE-2019-9704",
						NamespaceName: "ubuntu:14.04",
						Description:   "Vixie Cron before the 3.0pl1-133 Debian package allows local users to cause a denial of service (daemon crash) via a large crontab file because the calloc return value is not checked.",
						Link:          "https://ubuntu.com/security/CVE-2019-9704",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         2.9,
									"Score":               2.1,
									"Vectors":             "AV:L/AC:L/Au:N/C:N/I:N/A:P",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								},
								"LastModifiedDateTime": "2021-11-30T19:53Z",
								"PublishedDateTime":    "2019-03-12T01:29Z",
							},
						},
					},
					{
						Name:          "CVE-2019-9705",
						NamespaceName: "ubuntu:14.04",
						Description:   "Vixie Cron before the 3.0pl1-133 Debian package allows local users to cause a denial of service (memory consumption) via a large crontab file because an unlimited number of lines is accepted.",
						Link:          "https://ubuntu.com/security/CVE-2019-9705",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         2.9,
									"Score":               2.1,
									"Vectors":             "AV:L/AC:L/Au:N/C:N/I:N/A:P",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								},
								"LastModifiedDateTime": "2021-11-30T18:50Z",
								"PublishedDateTime":    "2019-03-12T01:29Z",
							},
						},
					},
					{
						Name:          "CVE-2019-9706",
						NamespaceName: "ubuntu:14.04",
						Description:   "Vixie Cron before the 3.0pl1-133 Debian package allows local users to cause a denial of service (use-after-free and daemon crash) because of a force_rescan_user error.",
						Link:          "https://ubuntu.com/security/CVE-2019-9706",
						Severity:      "Low",
						Metadata: map[string]interface{}{
							"NVD": map[string]interface{}{
								"CVSSv2": map[string]interface{}{
									"ExploitabilityScore": 3.9,
									"ImpactScore":         2.9,
									"Score":               2.1,
									"Vectors":             "AV:L/AC:L/Au:N/C:N/I:N/A:P",
								},
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         3.6,
									"Score":               5.5,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								},
								"LastModifiedDateTime": "2021-11-30T18:50Z",
								"PublishedDateTime":    "2019-03-12T01:29Z",
							},
						},
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
				FixedBy:       "3.1.23",
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
						Severity: "Important",
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
						FixedBy:  "3.1.12",
						Severity: "Critical",
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
						FixedBy:  "3.1.13",
						Severity: "Critical",
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
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         5.9,
									"Score":               7.8,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
								},
								"LastModifiedDateTime": "2021-05-20T12:48Z",
								"PublishedDateTime":    "2021-05-11T19:15Z",
							},
						},
						FixedBy:  "3.1.15",
						Severity: "Important",
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
						FixedBy:  "3.1.8",
						Severity: "Important",
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
						Severity: "Important",
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
						Severity: "Important",
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
						FixedBy:  "3.1.12",
						Severity: "Critical",
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
						FixedBy:  "3.1.13",
						Severity: "Critical",
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
								"CVSSv3": map[string]interface{}{
									"ExploitabilityScore": 1.8,
									"ImpactScore":         5.9,
									"Score":               7.8,
									"Vectors":             "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
								},
								"LastModifiedDateTime": "2021-05-20T12:48Z",
								"PublishedDateTime":    "2021-05-11T19:15Z",
							},
						},
						FixedBy:  "3.1.15",
						Severity: "Important",
					},
				},
				AddedBy:  "sha256:5bd47e7e8ad7786db14c79827b543615728f0e27567f5b05d4c13db29bb24c7a",
				Location: "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.0/",
				FixedBy:  "3.1.23",
			},
		},
	},
	{
		// Deletes directory containing jackson-databind:2.6.6.
		image:                   "docker.io/stackrox/sandbox:scannerremovejar",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
				FixedBy:  "2.12.6.1",
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
		image:     "docker.io/stackrox/sandbox:zookeeper-fatjar-remove",
		registry:  "https://registry-1.docker.io",
		username:  os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:  os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
		image:     "docker.io/stackrox/sandbox:oci-manifest",
		registry:  "https://registry-1.docker.io",
		username:  os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:  os.Getenv("DOCKER_IO_PULL_PASSWORD"),
		source:    "NVD",
		namespace: "ubuntu:16.04",
	},
	{
		// One of the images used for Red Hat Scanner Certification.
		image:                    "docker.io/stackrox/sandbox:jenkins-agent-maven-35-rhel7",
		registry:                 "https://registry-1.docker.io",
		username:                 os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                 os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
		image:                   "docker.io/stackrox/sandbox:jenkins-agent-maven-35-rhel7-chown",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
		image:                   "docker.io/stackrox/sandbox:nodejs-10",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
				AddedBy: "sha256:35ad9b4fba1fa6b00a6f266303348dc0cf9a7c341616e800c2738030c0f64167",
				FixedBy: "2.9.1-4.el8_3.1",
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
		// Had an issue where Scanner claimed jq 6.1-r1 was vulnerable to
		// a CVE fixed in 1.6_rc1-r0. We do NOT expect this version of
		// jq to be vulnerable to this CVE (CVE-2016-4074).
		image:     "docker.io/stackrox/sandbox:alpine-jq-1.6-r1",
		registry:  "https://registry-1.docker.io",
		username:  os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:  os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
		image:           "docker.io/richxsl/rhel7@sha256:8f3aae325d2074d2dc328cb532d6e7aeb0c588e15ddf847347038fe0566364d6",
		registry:        "https://registry-1.docker.io",
		source:          "NVD",
		uncertifiedRHEL: true,
		namespace:       "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "fipscheck",
				NamespaceName: "centos:7",
				VersionFormat: "rpm",
				Version:       "1.4.1-5.el7",
				AddedBy:       "sha256:1de5db95c59529b8423a336fac27e0bf8a9f4fced0fcc32377c9170ab481a8e9",
			},
		},
	},
	// The next two images have the same layer and thus verify lineage checks between different images
	// The first is a centos:7 image that has the package p11-kit. The second image is from fedora, and we
	// can't identify the OS, so it should not have p11-kit.
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
		image:     "quay.io/cgwalters/coreos-assembler@sha256:6ed6cd0006b6331d8cfd4a794afe7d2a87dc9019b80658a21b28d9941a97356d",
		registry:  "https://quay.io",
		source:    "NVD",
		namespace: "", // Fedora 28
		unexpectedFeatures: []apiV1.Feature{
			{
				Name:          "p11-kit",
				VersionFormat: "rpm",
				Version:       "0.23.5-3.el7",
			},
		},
	},
	{
		image:                    "alpine:3.13.0",
		registry:                 "https://registry-1.docker.io",
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
						Link:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30139",
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
						Link:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36159",
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
				AddedBy: "sha256:596ba82af5aaa3e2fd9d6f955b8b94f0744a2b60710e3c243ba3e4a467f051d1",
				FixedBy: "2.12.6-r0",
				Executables: []*v1.Executable{
					{
						Path: "/lib/libapk.so.3.12.0",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apk-tools", Version: "2.12.0-r4"},
							{Name: "libcrypto1.1", Version: "1.1.1i-r0"},
							{Name: "libssl1.1", Version: "1.1.1i-r0"},
							{Name: "musl", Version: "1.2.2_pre7-r0"},
							{Name: "zlib", Version: "1.2.11-r3"},
						},
					},
					{
						Path: "/sbin/apk",
						RequiredFeatures: []*v1.FeatureNameVersion{
							{Name: "apk-tools", Version: "2.12.0-r4"},
							{Name: "libcrypto1.1", Version: "1.1.1i-r0"},
							{Name: "libssl1.1", Version: "1.1.1i-r0"},
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
						Link:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28831",
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
				AddedBy: "sha256:596ba82af5aaa3e2fd9d6f955b8b94f0744a2b60710e3c243ba3e4a467f051d1",
				FixedBy: "1.32.1-r8",
				Executables: []*v1.Executable{
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
		image:                   "alpine:3.14.0",
		registry:                "https://registry-1.docker.io",
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
						Link:          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36159",
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
				AddedBy: "sha256:5843afab387455b37944e709ee8c78d7520df80f8d01cf7f861aae63beeddb6b",
				FixedBy: "2.12.6-r0",
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.14",
				VersionFormat: "apk",
				Version:       "1.33.1-r2",
				AddedBy:       "sha256:5843afab387455b37944e709ee8c78d7520df80f8d01cf7f861aae63beeddb6b",
				FixedBy:       "1.33.1-r7",
			},
		},
	},
	{
		image:                   "alpine:3.15.0",
		registry:                "https://registry-1.docker.io",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "alpine:v3.15",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "apk-tools",
				NamespaceName: "alpine:v3.15",
				VersionFormat: "apk",
				Version:       "2.12.7-r3",
				AddedBy:       "sha256:59bf1c3509f33515622619af21ed55bbe26d24913cedbca106468a5fb37a50c3",
			},
			{
				Name:          "busybox",
				NamespaceName: "alpine:v3.15",
				VersionFormat: "apk",
				Version:       "1.34.1-r3",
				AddedBy:       "sha256:59bf1c3509f33515622619af21ed55bbe26d24913cedbca106468a5fb37a50c3",
				FixedBy:       "1.34.1-r5",
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
		image:     "docker.io/anchore/anchore-engine:v0.9.4",
		registry:  "https://registry-1.docker.io",
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
		image:     "elastic/logstash:7.13.3",
		registry:  "https://registry-1.docker.io",
		source:    "NVD",
		namespace: "centos:7",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.9.1",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2020-9488",
						Description:   "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2020-9488",
						Severity:      "Low",
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
						Name:          "CVE-2021-44228",
						Description:   "In Apache Log4j2 versions up to and including 2.14.1 (excluding security release 2.12.2), the JNDI features used in configurations, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
						Severity:      "Critical",
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
						Name:          "CVE-2021-44832",
						Description:   "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:      "Moderate",
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
									"ImpactScore":         6.4,
									"Score":               6.0,
									"Vectors":             "AV:N/AC:M/Au:S/C:P/I:P/A:P",
								},
							},
						},
						FixedBy: "2.12.4",
					},
					{
						Name:          "CVE-2021-45046",
						Description:   "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern, resulting in an information leak and remote code execution in some environments and local code execution in all environments; remote code execution has been demonstrated on macOS but no other tested environments.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
						Severity:      "Critical",
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
						Name:          "CVE-2021-45105",
						Description:   "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:      "Moderate",
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
				AddedBy:  "sha256:c46de89b745ad8ba4400323d4ebc230a4b88cbbdbc92a862c92a743478abd617",
				Location: "usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-tcp-6.0.10-java/vendor/jar-dependencies/org/logstash/inputs/logstash-input-tcp/6.0.10/logstash-input-tcp-6.0.10.jar:log4j-core",
				FixedBy:  "2.12.4",
			},
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.14.0",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2021-44228",
						Description:   "In Apache Log4j2 versions up to and including 2.14.1 (excluding security release 2.12.2), the JNDI features used in configurations, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
						Severity:      "Critical",
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
						Name:          "CVE-2021-44832",
						Description:   "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:      "Moderate",
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
									"ImpactScore":         6.4,
									"Score":               6.0,
									"Vectors":             "AV:N/AC:M/Au:S/C:P/I:P/A:P",
								},
							},
						},
						FixedBy: "2.17.1",
					},
					{
						Name:          "CVE-2021-45046",
						Description:   "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern, resulting in an information leak and remote code execution in some environments and local code execution in all environments; remote code execution has been demonstrated on macOS but no other tested environments.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
						Severity:      "Critical",
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
						Name:          "CVE-2021-45105",
						Description:   "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:      "Moderate",
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
				AddedBy:  "sha256:c46de89b745ad8ba4400323d4ebc230a4b88cbbdbc92a862c92a743478abd617",
				Location: "usr/share/logstash/logstash-core/lib/jars/log4j-core-2.14.0.jar",
				FixedBy:  "2.17.1",
			},
		},
	},
	{
		image:     "docker.io/stackrox/sandbox:log4j-2-12-2",
		registry:  "https://registry-1.docker.io",
		username:  os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:  os.Getenv("DOCKER_IO_PULL_PASSWORD"),
		source:    "NVD",
		namespace: "ubuntu:20.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "log4j",
				VersionFormat: "JavaSourceType",
				Version:       "2.12.2",
				Vulnerabilities: []apiV1.Vulnerability{
					{
						Name:          "CVE-2020-9488",
						Description:   "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2020-9488",
						Severity:      "Low",
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
						Name:          "CVE-2021-44832",
						Description:   "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44832",
						Severity:      "Moderate",
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
									"ImpactScore":         6.4,
									"Score":               6.0,
									"Vectors":             "AV:N/AC:M/Au:S/C:P/I:P/A:P",
								},
							},
						},
						FixedBy: "2.12.4",
					},
					{
						Name:          "CVE-2021-45105",
						Description:   "Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
						Severity:      "Moderate",
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
		image:     "docker.io/busybox:1.35.0",
		registry:  "https://registry-1.docker.io",
		source:    "NVD",
		namespace: "busybox:1.35.0",
	},
	{
		image:                   "docker.io/stackrox/sandbox:springboot-2.6.5",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
						Name:          "CVE-2022-22965",
						Description:   "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
						Severity:      "Critical",
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
		image:                   "docker.io/stackrox/sandbox:springboot-2.6.5-flux",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
						Name:          "CVE-2022-22965",
						Description:   "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
						Severity:      "Critical",
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
		image:                   "docker.io/stackrox/sandbox:springboot-web-cloud-function-2.6.6",
		registry:                "https://registry-1.docker.io",
		username:                os.Getenv("DOCKER_IO_PULL_USERNAME"),
		password:                os.Getenv("DOCKER_IO_PULL_PASSWORD"),
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
						Name:          "CVE-2022-22963",
						Description:   "In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.",
						Link:          "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
						Severity:      "Critical",
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
		image:                   "ubuntu:22.04",
		registry:                "https://registry-1.docker.io",
		source:                  "NVD",
		onlyCheckSpecifiedVulns: true,
		namespace:               "ubuntu:22.04",
		expectedFeatures: []apiV1.Feature{
			{
				Name:          "adduser",
				NamespaceName: "ubuntu:22.04",
				VersionFormat: "dpkg",
				Version:       "3.118ubuntu5",
				AddedBy:       "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
			},
			{
				Name:          "apt",
				NamespaceName: "ubuntu:22.04",
				VersionFormat: "dpkg",
				Version:       "2.4.5",
				AddedBy:       "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
			},
		},
	},
}
