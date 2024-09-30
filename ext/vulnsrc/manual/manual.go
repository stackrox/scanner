package manual

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/apk"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/ext/vulnsrc"
)

var _ vulnsrc.Updater = (*updater)(nil)

type updater struct {
}

// Vulnerabilities lists vulnerabilities which may not already exist in the feeds for other distros.
var Vulnerabilities = []database.Vulnerability{
	/********** CVE-2024-47076 **********/

	// Alpine has not made it clear it is affected

	// Amazon claims to be unaffected in versions we support: https://explore.alas.aws.amazon.com/CVE-2024-47076.html

	// Debian 11
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "debian:11",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libcupsfilters` contains the code of the filters of the former `cups-filters` package as library functions to be used for the data format conversion tasks needed in Printer Applications. The `cfGetPrinterAttributes5` function in `libcupsfilters` does not sanitize IPP attributes returned from an IPP server. When these IPP attributes are used, for instance, to generate a PPD file, this can lead to attacker controlled data to be provided to the rest of the CUPS system.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47076",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:11",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.7-1+deb11u3",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian 12
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "debian:12",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libcupsfilters` contains the code of the filters of the former `cups-filters` package as library functions to be used for the data format conversion tasks needed in Printer Applications. The `cfGetPrinterAttributes5` function in `libcupsfilters` does not sanitize IPP attributes returned from an IPP server. When these IPP attributes are used, for instance, to generate a PPD file, this can lead to attacker controlled data to be provided to the rest of the CUPS system.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47076",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:12",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.17-3+deb12u1",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian unstable
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "debian:unstable",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libcupsfilters` contains the code of the filters of the former `cups-filters` package as library functions to be used for the data format conversion tasks needed in Printer Applications. The `cfGetPrinterAttributes5` function in `libcupsfilters` does not sanitize IPP attributes returned from an IPP server. When these IPP attributes are used, for instance, to generate a PPD file, this can lead to attacker controlled data to be provided to the rest of the CUPS system.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47076",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:unstable",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.17-5",
			},
			{
				Feature: database.Feature{
					Name: "libcupsfilters",
					Namespace: database.Namespace{
						Name:          "debian:unstable",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.0.0-3",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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

	// Ubuntu 20.04
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "ubuntu:20.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "cfGetPrinterAttributes5 does not validate IPP attributes returned from an IPP server",
		Link:        "https://ubuntu.com/security/CVE-2024-47076",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:20.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.27.4-1ubuntu0.3",
			},
		},
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
	// Ubuntu 22.04
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "cfGetPrinterAttributes5 does not validate IPP attributes returned from an IPP server",
		Link:        "https://ubuntu.com/security/CVE-2024-47076",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.15-0ubuntu1.3",
			},
		},
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
	// Ubuntu 24.04
	{
		Name: "CVE-2024-47076",
		Namespace: database.Namespace{
			Name:          "ubuntu:24.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "cfGetPrinterAttributes5 does not validate IPP attributes returned from an IPP server",
		Link:        "https://ubuntu.com/security/CVE-2024-47076",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "libcupsfilters",
					Namespace: database.Namespace{
						Name:          "ubuntu:24.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.0.0-0ubuntu7.1",
			},
		},
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

	/********** CVE-2024-47175 **********/

	// Alpine 3.19
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "alpine:v3.19",
			VersionFormat: apk.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://www.cve.org/CVERecord?id=CVE-2024-47175",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "alpine:v3.19",
						VersionFormat: apk.ParserName,
					},
				},
				Version: "2.4.9-r1",
			},
		},
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
	// Alpine 3.20
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "alpine:v3.20",
			VersionFormat: apk.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://www.cve.org/CVERecord?id=CVE-2024-47175",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "alpine:v3.20",
						VersionFormat: apk.ParserName,
					},
				},
				Version: "2.4.9-r1",
			},
		},
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
	// Alpine edge
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "alpine:edge",
			VersionFormat: apk.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://www.cve.org/CVERecord?id=CVE-2024-47175",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "alpine:edge",
						VersionFormat: apk.ParserName,
					},
				},
				Version: "2.4.10-r1",
			},
		},
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

	// Amazon claims to be unaffected in versions we support: https://explore.alas.aws.amazon.com/CVE-2024-47175.html

	// Debian 11
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "debian:11",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47175",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "debian:11",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.3.3op2-3+deb11u9",
			},
			{
				Feature: database.Feature{
					Name: "libppd",
					Namespace: database.Namespace{
						Name:          "debian:11",
						VersionFormat: dpkg.ParserName,
					},
				},
				// Unaffected.
				Version: versionfmt.MinVersion,
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian 12
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "debian:12",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47175",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "debian:12",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.4.2-3+deb12u8",
			},
			{
				Feature: database.Feature{
					Name: "libppd",
					Namespace: database.Namespace{
						Name:          "debian:12",
						VersionFormat: dpkg.ParserName,
					},
				},
				// Unaffected.
				Version: versionfmt.MinVersion,
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian unstable
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "debian:unstable",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `libppd` can be used for legacy PPD file support. The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP attributes when creating the PPD buffer. When used in combination with other functions such as `cfGetPrinterAttributes5`, can result in user controlled input and ultimately code execution via Foomatic. This vulnerability can be part of an exploit chain leading to remote code execution (RCE), as described in CVE-2024-47176.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47175",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "debian:unstable",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.4.10-2",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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

	// Ubuntu 16.04
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "ubuntu:16.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD buffer",
		Link:        "https://ubuntu.com/security/CVE-2024-47175",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "ubuntu:16.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 18.04
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "ubuntu:18.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD buffer",
		Link:        "https://ubuntu.com/security/CVE-2024-47175",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "ubuntu:18.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 20.04
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "ubuntu:20.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD buffer",
		Link:        "https://ubuntu.com/security/CVE-2024-47175",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "ubuntu:20.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.3.1-9ubuntu1.9",
			},
		},
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
	// Ubuntu 22.04
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD buffer",
		Link:        "https://ubuntu.com/security/CVE-2024-47175",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.4.1op1-1ubuntu4.11",
			},
		},
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
	// Ubuntu 24.04
	{
		Name: "CVE-2024-47175",
		Namespace: database.Namespace{
			Name:          "ubuntu:24.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD buffer",
		Link:        "https://ubuntu.com/security/CVE-2024-47175",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups",
					Namespace: database.Namespace{
						Name:          "ubuntu:24.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.4.7-1.2ubuntu7.3",
			},
			{
				Feature: database.Feature{
					Name: "libppd",
					Namespace: database.Namespace{
						Name:          "ubuntu:24.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2:2.0.0-0ubuntu4.1",
			},
		},
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

	/********** CVE-2024-47176 **********/

	// Alpine has not made it clear it is affected

	// Amazon Linux 2
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "amzn:2",
			VersionFormat: rpm.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL.",
		// Amazon currently does not have an ALAS link, so just the source of this data.
		Link:     "https://explore.alas.aws.amazon.com/CVE-2024-47176.html",
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "amzn:2",
						VersionFormat: rpm.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
				// Amazon used Red Hat's lower score.
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 2.8,
					"ImpactScore":         3.6,
					"Score":               6.5,
					"Vectors":             "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				},
			},
		},
	},

	// Debian 11
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "debian:11",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL.  Due to the service binding to `*:631 ( INADDR_ANY )`, multiple bugs in `cups-browsed` can be exploited in sequence to introduce a malicious printer to the system. This chain of exploits ultimately enables an attacker to execute arbitrary commands remotely on the target machine without authentication when a print job is started. This poses a significant security risk over the network. Notably, this vulnerability is particularly concerning as it can be exploited from the public internet, potentially exposing a vast number of systems to remote attacks if their CUPS services are enabled.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47176",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:11",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.7-1+deb11u3",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
				"CVSSv2": map[string]interface{}{
					"ExploitabilityScore": 0.0,
					"ImpactScore":         0.0,
					"Score":               0.0,
					"Vectors":             "",
				},
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Debian 12
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "debian:12",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL.  Due to the service binding to `*:631 ( INADDR_ANY )`, multiple bugs in `cups-browsed` can be exploited in sequence to introduce a malicious printer to the system. This chain of exploits ultimately enables an attacker to execute arbitrary commands remotely on the target machine without authentication when a print job is started. This poses a significant security risk over the network. Notably, this vulnerability is particularly concerning as it can be exploited from the public internet, potentially exposing a vast number of systems to remote attacks if their CUPS services are enabled.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47176",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:12",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.17-3+deb12u1",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
				"CVSSv2": map[string]interface{}{
					"ExploitabilityScore": 0.0,
					"ImpactScore":         0.0,
					"Score":               0.0,
					"Vectors":             "",
				},
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Debian unstable
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "debian:unstable",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL.  Due to the service binding to `*:631 ( INADDR_ANY )`, multiple bugs in `cups-browsed` can be exploited in sequence to introduce a malicious printer to the system. This chain of exploits ultimately enables an attacker to execute arbitrary commands remotely on the target machine without authentication when a print job is started. This poses a significant security risk over the network. Notably, this vulnerability is particularly concerning as it can be exploited from the public internet, potentially exposing a vast number of systems to remote attacks if their CUPS services are enabled.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47176",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:unstable",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.17-5",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
				"CVSSv2": map[string]interface{}{
					"ExploitabilityScore": 0.0,
					"ImpactScore":         0.0,
					"Score":               0.0,
					"Vectors":             "",
				},
				"CVSSv3": map[string]interface{}{
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},

	// Ubuntu 16.04
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "ubuntu:16.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Multiple bugs leading to info leak and remote code execution",
		Link:        "https://ubuntu.com/security/CVE-2024-47176",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:16.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Ubuntu 18.04
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "ubuntu:18.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Multiple bugs leading to info leak and remote code execution",
		Link:        "https://ubuntu.com/security/CVE-2024-47176",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:18.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Ubuntu 20.04
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "ubuntu:20.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Multiple bugs leading to info leak and remote code execution",
		Link:        "https://ubuntu.com/security/CVE-2024-47176",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:20.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.27.4-1ubuntu0.3",
			},
		},
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
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Ubuntu 22.04
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Multiple bugs leading to info leak and remote code execution",
		Link:        "https://ubuntu.com/security/CVE-2024-47176",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "1.28.15-0ubuntu1.3",
			},
		},
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
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},
	// Ubuntu 24.04
	{
		Name: "CVE-2024-47176",
		Namespace: database.Namespace{
			Name:          "ubuntu:24.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Multiple bugs leading to info leak and remote code execution",
		Link:        "https://ubuntu.com/security/CVE-2024-47176",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-browsed",
					Namespace: database.Namespace{
						Name:          "ubuntu:24.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "2.0.0-0ubuntu10.1",
			},
		},
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
					"ExploitabilityScore": 1.6,
					"ImpactScore":         6.0,
					"Score":               8.3,
					"Vectors":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
				},
			},
		},
	},

	/********** CVE-2024-47177 **********/

	// Alpine has not made it clear it is affected

	// Amazon claims to be unaffected in versions we support: https://explore.alas.aws.amazon.com/CVE-2024-47177.html

	// Debian 11
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "debian:11",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and cups-filters provides backends, filters, and other software for CUPS 2.x to use on non-Mac OS systems. Any value passed to `FoomaticRIPCommandLine` via a PPD file will be executed as a user controlled command. When combined with other logic bugs as described in CVE_2024-47176, this can lead to remote command execution.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47177",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:11",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian 12
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "debian:12",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and cups-filters provides backends, filters, and other software for CUPS 2.x to use on non-Mac OS systems. Any value passed to `FoomaticRIPCommandLine` via a PPD file will be executed as a user controlled command. When combined with other logic bugs as described in CVE_2024-47176, this can lead to remote command execution.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47177",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:12",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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
	// Debian unstable
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "debian:unstable",
			VersionFormat: dpkg.ParserName,
		},
		Description: "CUPS is a standards-based, open-source printing system, and cups-filters provides backends, filters, and other software for CUPS 2.x to use on non-Mac OS systems. Any value passed to `FoomaticRIPCommandLine` via a PPD file will be executed as a user controlled command. When combined with other logic bugs as described in CVE_2024-47176, this can lead to remote command execution.",
		Link:        "https://security-tracker.debian.org/tracker/CVE-2024-47177",
		// Debian did not assign a severity, so basing this on the score.
		Severity: database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "debian:unstable",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2024-09-26T16:00Z",
				"LastModifiedDateTime": "2024-09-30T16:00Z",
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

	// Ubuntu 16.04
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "ubuntu:16.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Command injection via FoomaticRIPCommandLine",
		Link:        "https://ubuntu.com/security/CVE-2024-47177",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:16.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 18.04
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "ubuntu:18.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Command injection via FoomaticRIPCommandLine",
		Link:        "https://ubuntu.com/security/CVE-2024-47177",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:18.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 20.04
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "ubuntu:20.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Command injection via FoomaticRIPCommandLine",
		Link:        "https://ubuntu.com/security/CVE-2024-47177",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:20.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 22.04
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Command injection via FoomaticRIPCommandLine",
		Link:        "https://ubuntu.com/security/CVE-2024-47177",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
	// Ubuntu 24.04
	{
		Name: "CVE-2024-47177",
		Namespace: database.Namespace{
			Name:          "ubuntu:24.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "Command injection via FoomaticRIPCommandLine",
		Link:        "https://ubuntu.com/security/CVE-2024-47177",
		// Ubuntu gave this a severity lower than the severity derived from the CVSS score.
		Severity: database.MediumSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "cups-filters",
					Namespace: database.Namespace{
						Name:          "ubuntu:24.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: versionfmt.MaxVersion,
			},
		},
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
}

func (u updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, _ error) {
	log.WithField("package", "Manual Entries").Info("Start fetching vulnerabilities")

	resp.Vulnerabilities = Vulnerabilities
	return
}

func (u updater) Clean() {}
