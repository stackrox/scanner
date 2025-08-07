package nvdloader

import (
	"os"
	"testing"

	jsonschema "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToJSON10(t *testing.T) {
	f, err := os.Open("testdata/nvdcve-2.0-2025.json")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})

	cveAPI, err := parseReader(f)
	require.NoError(t, err)

	cveFeed, err := toJSON10(cveAPI.Vulnerabilities)
	assert.NoError(t, err)

	expected := []*jsonschema.NVDCVEFeedJSON10DefCVEItem{
		{
			CVE: &jsonschema.CVEJSON40{
				CVEDataMeta: &jsonschema.CVEJSON40CVEDataMeta{
					ID: "CVE-2025-0168",
				},
				Description: &jsonschema.CVEJSON40Description{
					DescriptionData: []*jsonschema.CVEJSON40LangString{
						{
							Lang:  "en",
							Value: "A vulnerability classified as critical has been found in code-projects Job Recruitment 1.0. This affects an unknown part of the file /_parse/_feedback_system.php. The manipulation of the argument person leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.",
						},
					},
				},
			},
			Configurations: &jsonschema.NVDCVEFeedJSON10DefConfigurations{
				Nodes: []*jsonschema.NVDCVEFeedJSON10DefNode{
					{
						CPEMatch: []*jsonschema.NVDCVEFeedJSON10DefCPEMatch{
							{
								Cpe23Uri:   "cpe:2.3:a:anisha:job_recruitment:1.0:*:*:*:*:*:*:*",
								Vulnerable: true,
							},
						},
						Operator: "OR",
					},
				},
			},
			Impact: &jsonschema.NVDCVEFeedJSON10DefImpact{
				BaseMetricV3: &jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
					CVSSV3: &jsonschema.CVSSV30{
						AttackComplexity:      "LOW",
						AttackVector:          "NETWORK",
						AvailabilityImpact:    "NONE",
						BaseScore:             7.5,
						BaseSeverity:          "HIGH",
						ConfidentialityImpact: "HIGH",
						IntegrityImpact:       "NONE",
						PrivilegesRequired:    "NONE",
						Scope:                 "UNCHANGED",
						UserInteraction:       "NONE",
						VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Version:               "3.1",
					},
					ExploitabilityScore: 3.9,
					ImpactScore:         3.6,
				},
			},
			LastModifiedDate: "2025-02-25T21:26Z",
			PublishedDate:    "2025-01-01T14:15Z",
		},
		{
			CVE: &jsonschema.CVEJSON40{
				CVEDataMeta: &jsonschema.CVEJSON40CVEDataMeta{
					ID: "CVE-2025-22144",
				},
				Description: &jsonschema.CVEJSON40Description{
					DescriptionData: []*jsonschema.CVEJSON40LangString{
						{
							Lang:  "en",
							Value: "NamelessMC is a free, easy to use & powerful website software for Minecraft servers. A user with admincp.core.emails or admincp.users.edit permissions can validate users and an attacker can reset their password. When the account is successfully approved by email the reset code is NULL, but when the account is manually validated by a user with admincp.core.emails or admincp.users.edit permissions then the reset_code will no longer be NULL but empty. An attacker can request http://localhost/nameless/index.php?route=/forgot_password/&c= and reset the password. As a result an attacker may compromise another users password and take over their account. This issue has been addressed in release version 2.1.3 and all users are advised to upgrade. There are no known workarounds for this vulnerability.",
						},
					},
				},
			},
			Configurations: &jsonschema.NVDCVEFeedJSON10DefConfigurations{
				Nodes: []*jsonschema.NVDCVEFeedJSON10DefNode{
					{
						CPEMatch: []*jsonschema.NVDCVEFeedJSON10DefCPEMatch{
							{
								Cpe23Uri:            "cpe:2.3:a:namelessmc:nameless:*:*:*:*:*:*:*:*",
								VersionEndExcluding: "2.1.3",
								Vulnerable:          true,
							},
						},
						Operator: "OR",
					},
				},
			},
			Impact: &jsonschema.NVDCVEFeedJSON10DefImpact{
				BaseMetricV3: &jsonschema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
					CVSSV3: &jsonschema.CVSSV30{
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
			LastModifiedDate: "2025-05-13T15:42Z",
			PublishedDate:    "2025-01-13T20:15Z",
		},
	}

	assert.ElementsMatch(t, expected, cveFeed)
}
