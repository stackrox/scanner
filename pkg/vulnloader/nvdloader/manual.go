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
						Value: `Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (>2.10) this behavior can be mitigated by setting system property "log4j2.formatMsgNoLookups" to “true” or by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). Java 8u121 (see https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) protects against remote code execution by defaulting "com.sun.jndi.rmi.object.trustURLCodebase" and "com.sun.jndi.cosnaming.object.trustURLCodebase" to "false".`,
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
							VersionStartIncluding: "2.0.1",
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
		LastModifiedDate: "2021-12-13T00:00Z",
		PublishedDate:    "2021-12-10T00:00Z",
	},
}
