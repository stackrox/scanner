package nvdloader

import "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"

var manuallyEnrichedVulns = map[string]*schema.NVDCVEFeedJSON10DefCVEItem{
	"CVE-2021-44228": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2021-44228",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `In Apache Log4j2 versions up to and including 2.14.1 (excluding security release 2.12.2), the JNDI features used in configurations, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://logging.apache.org/log4j/2.x/security.html",
					},
				},
			},
		},
		Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
			CVEDataVersion: "4.0",
			Nodes: []*schema.NVDCVEFeedJSON10DefNode{
				{
					CPEMatch: []*schema.NVDCVEFeedJSON10DefCPEMatch{
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.15.0",
							VersionStartIncluding: "2.13.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.12.2",
							VersionStartIncluding: "2.4.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.3.1",
							VersionStartIncluding: "2.0.0", // Red Hat says 2.0.0, and I trust them more.
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "LOW",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             10.0,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "CHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         6.0,
			},
		},
		LastModifiedDate: "2021-12-26T00:00Z",
		PublishedDate:    "2021-12-10T00:00Z",
	},
	"CVE-2021-45046": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2021-45046",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data using a JNDI Lookup pattern, resulting in an information leak and remote code execution in some environments and local code execution in all environments; remote code execution has been demonstrated on macOS but no other tested environments.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://logging.apache.org/log4j/2.x/security.html",
					},
				},
			},
		},
		Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
			CVEDataVersion: "4.0",
			Nodes: []*schema.NVDCVEFeedJSON10DefNode{
				{
					CPEMatch: []*schema.NVDCVEFeedJSON10DefCPEMatch{
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.16.0",
							VersionStartIncluding: "2.13.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.12.2",
							VersionStartIncluding: "2.4.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.3.1",
							VersionStartIncluding: "2.0.0", // Red Hat says 2.0.0, and I trust them more.
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "HIGH",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             9.0,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "CHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 2.2,
				ImpactScore:         6.0,
			},
		},
		LastModifiedDate: "2021-12-26T00:00Z",
		PublishedDate:    "2021-12-13T00:00Z",
	},
	"CVE-2021-45105": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2021-45105",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate the process. This is also known as a DOS (Denial of Service) attack.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://logging.apache.org/log4j/2.x/security.html",
					},
				},
			},
		},
		Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
			CVEDataVersion: "4.0",
			Nodes: []*schema.NVDCVEFeedJSON10DefNode{
				{
					CPEMatch: []*schema.NVDCVEFeedJSON10DefCPEMatch{
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.17.0",
							VersionStartIncluding: "2.13.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.12.3",
							VersionStartIncluding: "2.4.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "2.3.1",
							VersionStartIncluding: "2.0.0", // Red Hat says 2.0.0, and I trust them more.
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "HIGH",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             5.9,
					ConfidentialityImpact: "NONE",
					IntegrityImpact:       "NONE",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 2.2,
				ImpactScore:         3.6,
			},
		},
		LastModifiedDate: "2022-01-13T00:00Z",
		PublishedDate:    "2021-12-19T00:00Z",
	},
	"CVE-2022-0811": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2022-0811",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `A flaw introduced in CRI-O version 1.19 which an attacker can use to bypass the safeguards and set arbitrary kernel parameters on the host. As a result, anyone with rights to deploy a pod on a Kubernetes cluster that uses the CRI-O runtime can abuse the “kernel.core_pattern” kernel parameter to achieve container escape and arbitrary code execution as root on any node in the cluster.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://access.redhat.com/security/cve/CVE-2022-0811",
					},
				},
			},
		},
		Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
			CVEDataVersion: "4.0",
			Nodes: []*schema.NVDCVEFeedJSON10DefNode{
				{
					CPEMatch: []*schema.NVDCVEFeedJSON10DefCPEMatch{
						{
							Cpe23Uri:              "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "1.19.6",
							VersionStartIncluding: "1.19.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "1.20.7",
							VersionStartIncluding: "1.20.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "1.21.6",
							VersionStartIncluding: "1.21.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "1.22.3",
							VersionStartIncluding: "1.22.0",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   "1.23.2",
							VersionStartIncluding: "1.23.0",
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "LOW",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             8.8,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "LOW",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 2.8,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2022-03-16T00:00Z",
		PublishedDate:    "2021-03-16T00:00Z",
	},
}
