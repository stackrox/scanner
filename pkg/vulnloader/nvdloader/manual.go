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
		LastModifiedDate: "2021-12-16T00:00Z",
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
						Value: `It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 restricts JNDI LDAP lookups to localhost by default. Note that previous mitigations involving configuration such as to set the system property log4j2.formatMsgNoLookups to true do NOT mitigate this specific vulnerability.`,
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
					AvailabilityImpact:    "LOW",
					BaseScore:             3.7,
					ConfidentialityImpact: "NONE",
					IntegrityImpact:       "NONE",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
					Version:               "3.1",
				},
				ExploitabilityScore: 2.2,
				ImpactScore:         1.4,
			},
		},
		LastModifiedDate: "2021-12-16T00:00Z",
		PublishedDate:    "2021-12-13T00:00Z",
	},
}
