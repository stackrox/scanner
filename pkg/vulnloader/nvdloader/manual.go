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
							Cpe23Uri:              `cpe:2.3:a:kubernetes:cri\-o:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "1.19.6",
							VersionStartIncluding: "1.19.0",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:kubernetes:cri\-o:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "1.20.7",
							VersionStartIncluding: "1.20.0",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:kubernetes:cri\-o:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "1.21.6",
							VersionStartIncluding: "1.21.0",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:kubernetes:cri\-o:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "1.22.3",
							VersionStartIncluding: "1.22.0",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:kubernetes:cri\-o:*:*:*:*:*:*:*:*`,
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
		PublishedDate:    "2022-03-16T00:00Z",
	},
	"CVE-2022-22963": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2022-22963",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://tanzu.vmware.com/security/cve-2022-22963",
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
							Cpe23Uri:              `cpe:2.3:a:apache:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "3.2.3",
							VersionStartIncluding: "3.2.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:apache:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "3.1.7",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:springframework:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "3.2.3",
							VersionStartIncluding: "3.2.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:springframework:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "3.1.7",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:pivotal:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "3.2.3",
							VersionStartIncluding: "3.2.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:pivotal:spring\-cloud\-function\-core:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "3.1.7",
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
					BaseScore:             9.8,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Version:               "3.0",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2022-03-31T00:00Z",
		PublishedDate:    "2022-03-29T00:00Z",
	},
	"CVE-2022-22965": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2022-22965",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: `A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.`,
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://tanzu.vmware.com/security/cve-2022-22965",
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
							Cpe23Uri:              `cpe:2.3:a:apache:spring\-webmvc:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "5.3.18",
							VersionStartIncluding: "5.3.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:apache:spring\-webmvc:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "5.2.20",
						},
						{
							Cpe23Uri:              `cpe:2.3:a:apache:spring\-webflux:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "5.3.18",
							VersionStartIncluding: "5.3.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:apache:spring\-webflux:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "5.2.20",
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
					BaseScore:             9.8,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Version:               "3.0",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2022-03-31T00:00Z",
		PublishedDate:    "2022-03-31T00:00Z",
	},
	"CVE-2022-22978": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ID: "CVE-2022-22978",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "In Spring Security versions 5.5.6 and 5.6.3 and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers.\n\nApplications using RegexRequestMatcher with '.' in the regular expression are possibly vulnerable to an authorization bypass.",
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name: "https://tanzu.vmware.com/security/cve-2022-22978",
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
							Cpe23Uri:              `cpe:2.3:a:vmware:spring\-security\-web:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "5.6.4",
							VersionStartIncluding: "5.6.0",
						},
						{
							Cpe23Uri:            `cpe:2.3:a:vmware:spring\-security\-web:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "5.5.7",
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
					AvailabilityImpact:    "NONE",
					BaseScore:             8.2,
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "LOW",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         4.2,
			},
		},
		LastModifiedDate: "2022-05-16T00:00Z",
		PublishedDate:    "2022-05-16T00:00Z",
	},
	"CVE-2017-5638": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "security@apache.org",
				ID:       "CVE-2017-5638",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.",
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://isc.sans.edu/diary/22169",
						Refsource: "MISC",
						Tags: []string{
							"Technical Description",
							"Third Party Advisory",
						},
						URL: "https://isc.sans.edu/diary/22169",
					},
					{
						Name:      "https://github.com/rapid7/metasploit-framework/issues/8064",
						Refsource: "MISC",
						Tags: []string{
							"Exploit",
						},
						URL: "https://github.com/rapid7/metasploit-framework/issues/8064",
					},
					{
						Name:      "https://git1-us-west.apache.org/repos/asf?p=struts.git;a=commit;h=6b8272ce47160036ed120a48345d9aa884477228",
						Refsource: "CONFIRM",
						Tags: []string{
							"Patch",
						},
						URL: "https://git1-us-west.apache.org/repos/asf?p=struts.git;a=commit;h=6b8272ce47160036ed120a48345d9aa884477228",
					},
					{
						Name:      "https://git1-us-west.apache.org/repos/asf?p=struts.git;a=commit;h=352306493971e7d5a756d61780d57a76eb1f519a",
						Refsource: "CONFIRM",
						Tags: []string{
							"Patch",
						},
						URL: "https://git1-us-west.apache.org/repos/asf?p=struts.git;a=commit;h=352306493971e7d5a756d61780d57a76eb1f519a",
					},
					{
						Name:      "https://cwiki.apache.org/confluence/display/WW/S2-045",
						Refsource: "CONFIRM",
						Tags: []string{
							"Mitigation",
							"Vendor Advisory",
						},
						URL: "https://cwiki.apache.org/confluence/display/WW/S2-045",
					},
					{
						Name:      "http://blog.trendmicro.com/trendlabs-security-intelligence/cve-2017-5638-apache-struts-vulnerability-remote-code-execution/",
						Refsource: "MISC",
						Tags: []string{
							"Technical Description",
							"Third Party Advisory",
						},
						URL: "http://blog.trendmicro.com/trendlabs-security-intelligence/cve-2017-5638-apache-struts-vulnerability-remote-code-execution/",
					},
					{
						Name:      "http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html",
						Refsource: "MISC",
						Tags: []string{
							"Technical Description",
							"Third Party Advisory",
						},
						URL: "http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html",
					},
					{
						Name:      "https://packetstormsecurity.com/files/141494/S2-45-poc.py.txt",
						Refsource: "MISC",
						Tags: []string{
							"Exploit",
							"VDB Entry",
						},
						URL: "https://packetstormsecurity.com/files/141494/S2-45-poc.py.txt",
					},
					{
						Name:      "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html",
						Refsource: "MISC",
						Tags: []string{
							"Third Party Advisory",
						},
						URL: "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html",
					},
					{
						Name:      "https://github.com/mazen160/struts-pwn",
						Refsource: "MISC",
						Tags: []string{
							"Exploit",
						},
						URL: "https://github.com/mazen160/struts-pwn",
					},
					{
						Name:      "41570",
						Refsource: "EXPLOIT-DB",
						Tags: []string{
							"Exploit",
							"VDB Entry",
						},
						URL: "https://exploit-db.com/exploits/41570",
					},
					{
						Name:      "https://twitter.com/theog150/status/841146956135124993",
						Refsource: "MISC",
						Tags: []string{
							"Third Party Advisory",
						},
						URL: "https://twitter.com/theog150/status/841146956135124993",
					},
					{
						Name:      "https://arstechnica.com/security/2017/03/critical-vulnerability-under-massive-attack-imperils-high-impact-sites/",
						Refsource: "MISC",
						Tags: []string{
							"Press/Media Coverage",
						},
						URL: "https://arstechnica.com/security/2017/03/critical-vulnerability-under-massive-attack-imperils-high-impact-sites/",
					},
					{
						Name:      "96729",
						Refsource: "BID",
						Tags: []string{
							"Third Party Advisory",
							"VDB Entry",
						},
						URL: "http://www.securityfocus.com/bid/96729",
					},
					{
						Name:      "http://www.eweek.com/security/apache-struts-vulnerability-under-attack.html",
						Refsource: "MISC",
						Tags: []string{
							"Press/Media Coverage",
						},
						URL: "http://www.eweek.com/security/apache-struts-vulnerability-under-attack.html",
					},
					{
						Name:      "https://www.imperva.com/blog/2017/03/cve-2017-5638-new-remote-code-execution-rce-vulnerability-in-apache-struts-2/",
						Refsource: "MISC",
						URL:       "https://www.imperva.com/blog/2017/03/cve-2017-5638-new-remote-code-execution-rce-vulnerability-in-apache-struts-2/",
					},
					{
						Name:      "https://support.lenovo.com/us/en/product_security/len-14200",
						Refsource: "CONFIRM",
						URL:       "https://support.lenovo.com/us/en/product_security/len-14200",
					},
					{
						Name:      "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03723en_us",
						Refsource: "CONFIRM",
						URL:       "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03723en_us",
					},
					{
						Name:      "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbgn03733en_us",
						Refsource: "CONFIRM",
						URL:       "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbgn03733en_us",
					},
					{
						Name:      "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbgn03749en_us",
						Refsource: "CONFIRM",
						URL:       "https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbgn03749en_us",
					},
					{
						Name:      "1037973",
						Refsource: "SECTRACK",
						URL:       "http://www.securitytracker.com/id/1037973",
					},
					{
						Name:      "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html",
						Refsource: "CONFIRM",
						URL:       "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html",
					},
					{
						Name:      "41614",
						Refsource: "EXPLOIT-DB",
						URL:       "https://www.exploit-db.com/exploits/41614/",
					},
					{
						Name:      "https://www.symantec.com/security-center/network-protection-security-advisories/SA145",
						Refsource: "CONFIRM",
						URL:       "https://www.symantec.com/security-center/network-protection-security-advisories/SA145",
					},
					{
						Name:      "https://struts.apache.org/docs/s2-046.html",
						Refsource: "CONFIRM",
						URL:       "https://struts.apache.org/docs/s2-046.html",
					},
					{
						Name:      "https://struts.apache.org/docs/s2-045.html",
						Refsource: "CONFIRM",
						URL:       "https://struts.apache.org/docs/s2-045.html",
					},
					{
						Name:      "https://cwiki.apache.org/confluence/display/WW/S2-046",
						Refsource: "CONFIRM",
						URL:       "https://cwiki.apache.org/confluence/display/WW/S2-046",
					},
					{
						Name:      "VU#834067",
						Refsource: "CERT-VN",
						URL:       "https://www.kb.cert.org/vuls/id/834067",
					},
					{
						Name:      "https://security.netapp.com/advisory/ntap-20170310-0001/",
						Refsource: "CONFIRM",
						URL:       "https://security.netapp.com/advisory/ntap-20170310-0001/",
					},
					{
						Name:      "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2017-002.txt",
						Refsource: "CONFIRM",
						URL:       "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2017-002.txt",
					},
					{
						Name:      "[announce] 20200131 Apache Software Foundation Security Report: 2019",
						Refsource: "MLIST",
						URL:       "https://lists.apache.org/thread.html/r6d03e45b81eab03580cf7f8bb51cb3e9a1b10a2cc0c6a2d3cc92ed0c@%3Cannounce.apache.org%3E",
					},
					{
						Name:      "[announce] 20210125 Apache Software Foundation Security Report: 2020",
						Refsource: "MLIST",
						URL:       "https://lists.apache.org/thread.html/r90890afea72a9571d666820b2fe5942a0a5f86be406fa31da3dd0922@%3Cannounce.apache.org%3E",
					},
					{
						Name:      "[announce] 20210223 Re: Apache Software Foundation Security Report: 2020",
						Refsource: "MLIST",
						URL:       "https://lists.apache.org/thread.html/r1125f3044a0946d1e7e6f125a6170b58d413ebd4a95157e4608041c7@%3Cannounce.apache.org%3E",
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
							Cpe23Uri:              "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
							Vulnerable:            true,
							VersionStartIncluding: "2.3.5",
							VersionEndExcluding:   "2.3.32",
						},
						{
							Cpe23Uri:              "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
							Vulnerable:            true,
							VersionStartIncluding: "2.5",
							VersionEndExcluding:   "2.5.10.1",
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV2: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
				AcInsufInfo: false,
				CVSSV2: &schema.CVSSV20{
					AccessComplexity:      "LOW",
					AccessVector:          "NETWORK",
					Authentication:        "NONE",
					AvailabilityImpact:    "COMPLETE",
					BaseScore:             10,
					ConfidentialityImpact: "COMPLETE",
					IntegrityImpact:       "COMPLETE",
					VectorString:          "AV:N/AC:L/Au:N/C:C/I:C/A:C",
					Version:               "2.0",
				},
				ExploitabilityScore:     10,
				ImpactScore:             10,
				ObtainAllPrivilege:      false,
				ObtainOtherPrivilege:    false,
				ObtainUserPrivilege:     false,
				Severity:                "HIGH",
				UserInteractionRequired: false,
			},
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "LOW",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             10,
					BaseSeverity:          "CRITICAL",
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "CHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					Version:               "3.0",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         6,
			},
		},
		LastModifiedDate: "2021-02-24T12:15Z",
		PublishedDate:    "2017-03-11T02:59Z",
	},
	// CVE-2021-41411 was not being detected for `org.drools.drools-core-6.4.0.Final.jar`.
	// This entry adds an additional CPE URI (in addition to what exists in NVD) to
	// enable matching.
	"CVE-2021-41411": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "cve@mitre.org",
				ID:       "CVE-2021-41411",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "drools <=7.59.x is affected by an XML External Entity (XXE) vulnerability in KieModuleMarshaller.java. The Validator class is not used correctly, resulting in the XXE injection vulnerability.",
					},
				},
			},
			Problemtype: &schema.CVEJSON40Problemtype{
				ProblemtypeData: []*schema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*schema.CVEJSON40LangString{
							{
								Lang:  "en",
								Value: "CWE-611",
							},
						},
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://github.com/kiegroup/drools/pull/3808",
						Refsource: "MISC",
						Tags:      []string{"Patch", "Third Party Advisory"},
						URL:       "https://github.com/kiegroup/drools/pull/3808",
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
							Cpe23Uri:            `cpe:2.3:a:redhat:drools:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "7.60.0.Final",
							Vulnerable:          true,
						},
						{
							Cpe23Uri:            `cpe:2.3:a:drools:drools:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "7.60.0.Final",
							Vulnerable:          true,
						},
					},
					Operator: "OR",
				},
			},
		},
		Impact: &schema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV2: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
				CVSSV2: &schema.CVSSV20{
					AccessComplexity:      "LOW",
					AccessVector:          "NETWORK",
					Authentication:        "NONE",
					AvailabilityImpact:    "PARTIAL",
					BaseScore:             7.5,
					ConfidentialityImpact: "PARTIAL",
					IntegrityImpact:       "PARTIAL",
					VectorString:          "AV:N/AC:L/Au:N/C:P/I:P/A:P",
					Version:               "2.0",
				},
				ExploitabilityScore: 10,
				ImpactScore:         6.4,
				Severity:            "HIGH",
			},
			BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &schema.CVSSV30{
					AttackComplexity:      "LOW",
					AttackVector:          "NETWORK",
					AvailabilityImpact:    "HIGH",
					BaseScore:             9.8,
					BaseSeverity:          "CRITICAL",
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2023-07-17T21:00Z",
		PublishedDate:    "2023-07-17T21:00Z",
	},
	////////////////////////////////////////////
	// Start cURL and libcurl vulnerabilities //
	////////////////////////////////////////////
	// Each vendor already has an entry for this. Only NVD is missing an entry, so we fill it here.
	"CVE-2023-38545": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "cve@mitre.org",
				ID:       "CVE-2023-38545",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang: "en",
						Value: `This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.

When curl is asked to pass along the hostname to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that hostname can be is 255 bytes.

If the hostname is detected to be longer than 255 bytes, curl switches to local name resolving and instead passes on the resolved address only to the proxy. Due to a bug, the local variable that means "let the host resolve the name" could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention, copy the too long hostname to the target buffer instead of copying just the resolved address there.`,
					},
				},
			},
			Problemtype: &schema.CVEJSON40Problemtype{
				ProblemtypeData: []*schema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*schema.CVEJSON40LangString{
							{
								Lang:  "en",
								Value: "CWE-122",
							},
						},
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://curl.se/docs/CVE-2023-38545.html",
						Refsource: "MISC",
						Tags:      []string{"Patch", "Third Party Advisory"},
						URL:       "https://curl.se/docs/CVE-2023-38545.html",
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
							Cpe23Uri:              `cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "8.4.0",
							VersionStartIncluding: "7.69.0",
							Vulnerable:            true,
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
					BaseScore:             7.5,
					BaseSeverity:          "HIGH",
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "REQUIRED",
					VectorString:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 1.6,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2023-10-11T00:00Z",
		PublishedDate:    "2023-10-11T00:00Z",
	},
	// Each vendor already has an entry for this. Only NVD is missing an entry, so we fill it here.
	"CVE-2023-38546": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "cve@mitre.org",
				ID:       "CVE-2023-38546",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang: "en",
						Value: `This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the specific series of conditions are met.

libcurl performs transfers. In its API, an application creates "easy handles" that are the individual handles for single transfers.

libcurl provides a function call that duplicates an easy handle called curl_easy_duphandle.

If a transfer has cookies enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned version of the handle would instead store the file name as none (using the four ASCII letters, no quotes).

Subsequent use of the cloned handle that does not explicitly set a source to load cookies from would then inadvertently load cookies from a file named none - if such a file exists and is readable in the current directory of the program using libcurl. And if using the correct file format of course.`,
					},
				},
			},
			Problemtype: &schema.CVEJSON40Problemtype{
				ProblemtypeData: []*schema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*schema.CVEJSON40LangString{
							{
								Lang:  "en",
								Value: "CWE-73",
							},
						},
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://curl.se/docs/CVE-2023-38546.html",
						Refsource: "MISC",
						Tags:      []string{"Patch", "Third Party Advisory"},
						URL:       "https://curl.se/docs/CVE-2023-38546.html",
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
							Cpe23Uri:              `cpe:2.3:a:ubuntu:libcurl:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "8.4.0",
							VersionStartIncluding: "7.9.1",
							Vulnerable:            true,
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
					BaseScore:             5.0,
					BaseSeverity:          "MEDIUM",
					ConfidentialityImpact: "LOW",
					IntegrityImpact:       "LOW",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "REQUIRED",
					VectorString:          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L",
					Version:               "3.1",
				},
				ExploitabilityScore: 1.6,
				ImpactScore:         3.4,
			},
		},
		LastModifiedDate: "2023-10-11T00:00Z",
		PublishedDate:    "2023-10-11T00:00Z",
	},
	//////////////////////////////////////////
	// End cURL and libcurl vulnerabilities //
	//////////////////////////////////////////
	////////////////////////////////////
	// Start HTTP/2 Rapid Reset vulns //
	////////////////////////////////////
	"CVE-2023-39325": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "cve@mitre.org",
				ID:       "CVE-2023-39325",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "A flaw was found in the handling of multiplexed streams in the http/2 protocol. A client can repeatedly make requests for a new multiplex streams and immediately send a RST_STREAM frame to cancel them. This creates extra work for the server setting up and tearing down the streams while not hitting any server-side limit for maximum number of active streams per connection, resulting in a denial of service due to server resource consumption.",
					},
				},
			},
			Problemtype: &schema.CVEJSON40Problemtype{
				ProblemtypeData: []*schema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*schema.CVEJSON40LangString{
							{
								Lang:  "en",
								Value: "CWE-611",
							},
						},
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://github.com/golang/go/issues/63417",
						Refsource: "MISC",
						Tags:      []string{"Patch", "Third Party Advisory"},
						URL:       "https://github.com/golang/go/issues/63417",
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
							Cpe23Uri:            `cpe:2.3:a:go:http2:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "0.17.0",
							Vulnerable:          true,
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
					BaseScore:             7.5,
					BaseSeverity:          "HIGH",
					ConfidentialityImpact: "NONE",
					IntegrityImpact:       "NONE",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         3.6,
			},
		},
		LastModifiedDate: "2023-10-11T00:00Z",
		PublishedDate:    "2023-10-11T00:00Z",
	},
	"CVE-2023-44487": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "cve@mitre.org",
				ID:       "CVE-2023-44487",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
					},
				},
			},
			Problemtype: &schema.CVEJSON40Problemtype{
				ProblemtypeData: []*schema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*schema.CVEJSON40LangString{
							{
								Lang:  "en",
								Value: "CWE-611",
							},
						},
					},
				},
			},
			References: &schema.CVEJSON40References{
				ReferenceData: []*schema.CVEJSON40Reference{
					{
						Name:      "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
						Refsource: "MISC",
						Tags:      []string{"Patch", "Third Party Advisory"},
						URL:       "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
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
							Cpe23Uri:            `cpe:2.3:a:go:http2:*:*:*:*:*:*:*:*`,
							VersionEndExcluding: "0.17.0",
							Vulnerable:          true,
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
					BaseScore:             7.5,
					BaseSeverity:          "HIGH",
					ConfidentialityImpact: "NONE",
					IntegrityImpact:       "NONE",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         3.6,
			},
		},
		LastModifiedDate: "2023-10-11T00:00Z",
		PublishedDate:    "2023-10-11T00:00Z",
	},
	//////////////////////////////////
	// End HTTP/2 Rapid Reset vulns //
	//////////////////////////////////

	// CVE-2023-32697 was not being detected for `org.xerial.sqlite-jdbc-3.41.2.1.jar`.
	// This entry adds an additional CPE URI to enable matching.
	"CVE-2023-32697": {
		CVE: &schema.CVEJSON40{
			CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
				ASSIGNER: "",
				ID:       "CVE-2023-32697",
			},
			DataFormat:  "",
			DataType:    "",
			DataVersion: "",
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: "SQLite JDBC is a library for accessing and creating SQLite database files in Java. Sqlite-jdbc addresses a remote code execution vulnerability via JDBC URL. This issue impacting versions 3.6.14.1 through 3.41.2.1 and has been fixed in version 3.41.2.2.\n",
					},
				},
			},
			Problemtype: nil,
			References:  nil,
		},
		Configurations: &schema.NVDCVEFeedJSON10DefConfigurations{
			CVEDataVersion: "",
			Nodes: []*schema.NVDCVEFeedJSON10DefNode{
				{
					CPEMatch: []*schema.NVDCVEFeedJSON10DefCPEMatch{
						{
							Cpe23Uri:              `cpe:2.3:a:sqlite_jdbc_project:sqlite_jdbc:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "3.41.2.2",
							VersionStartIncluding: "3.6.14.1",
							Vulnerable:            true,
						},
						{
							Cpe23Uri:              `cpe:2.3:a:xerial:sqlite-jdbc:*:*:*:*:*:*:*:*`,
							VersionEndExcluding:   "3.41.2.2",
							VersionStartIncluding: "3.6.14.1",
							Vulnerable:            true,
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
					BaseScore:             9.8,
					BaseSeverity:          "CRITICAL",
					ConfidentialityImpact: "HIGH",
					IntegrityImpact:       "HIGH",
					PrivilegesRequired:    "NONE",
					Scope:                 "UNCHANGED",
					UserInteraction:       "NONE",
					VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Version:               "3.1",
				},
				ExploitabilityScore: 3.9,
				ImpactScore:         5.9,
			},
		},
		LastModifiedDate: "2024-04-04T00:00Z",
		PublishedDate:    "2023-05-23T23:15Z",
	},
}
