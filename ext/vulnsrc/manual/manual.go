package manual

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/vulnsrc"
)

var _ vulnsrc.Updater = (*updater)(nil)

type updater struct {
}

// Vulnerabilities lists vulnerabilities which may not already exist in the feeds for other distros.
var Vulnerabilities = []database.Vulnerability{
	{
		Name: "CVE-2022-3602",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).",
		Link:        "https://ubuntu.com/security/CVE-2022-3602",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.2-0ubuntu1.7",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2022-11-01T16:00Z",
				"LastModifiedDateTime": "2022-11-02T16:00Z",
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
	{
		Name: "CVE-2022-3602",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.10",
			VersionFormat: dpkg.ParserName,
		},
		Description: "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).",
		Link:        "https://ubuntu.com/security/CVE-2022-3602",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.10",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.5-2ubuntu2",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2022-11-01T16:00Z",
				"LastModifiedDateTime": "2022-11-02T16:00Z",
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
	{
		Name: "CVE-2022-3786",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.04",
			VersionFormat: dpkg.ParserName,
		},
		Description: "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).",
		Link:        "https://ubuntu.com/security/CVE-2022-3786",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.04",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.2-0ubuntu1.7",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2022-11-01T16:00Z",
				"LastModifiedDateTime": "2022-11-02T16:00Z",
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
		Name: "CVE-2022-3786",
		Namespace: database.Namespace{
			Name:          "ubuntu:22.10",
			VersionFormat: dpkg.ParserName,
		},
		Description: "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).",
		Link:        "https://ubuntu.com/security/CVE-2022-3786",
		Severity:    database.HighSeverity,
		FixedIn: []database.FeatureVersion{
			{
				Feature: database.Feature{
					Name: "openssl",
					Namespace: database.Namespace{
						Name:          "ubuntu:22.10",
						VersionFormat: dpkg.ParserName,
					},
				},
				Version: "3.0.5-2ubuntu2",
			},
		},
		Metadata: map[string]interface{}{
			"NVD": map[string]interface{}{
				"PublishedDateTime":    "2022-11-01T16:00Z",
				"LastModifiedDateTime": "2022-11-02T16:00Z",
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
}

func (u updater) Update(_ vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, _ error) {
	log.WithField("package", "Manual Entries").Info("Start fetching vulnerabilities")

	resp.Vulnerabilities = Vulnerabilities
	return
}

func (u updater) Clean() {}
