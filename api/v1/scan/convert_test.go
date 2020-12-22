package scan

import (
	"encoding/json"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedVuln struct {
	Name        string
	Description string
	Link        string
	Metadata    *types.Metadata
	FixedBy     string
}

func TestConvertK8sVulnerabilities(t *testing.T) {
	testCases := []struct {
		version  string
		cves     []*validation.CVESchema
		expected []expectedVuln
	}{
		{
			version: "1.0.0",
			cves: []*validation.CVESchema{
				{
					CVE:         "CVE-2020-1234",
					Description: "test1",
					IssueURL:    "issueUrl",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV2:  3.5,
							VectorV2: "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
						Kubernetes: &validation.KubernetesSchema{
							ScoreV3:  6.3,
							VectorV3: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					Affected: []validation.AffectedSchema{
						{
							Range:   "<= 1.0.0",
							FixedBy: "1.0.1",
						},
					},
				},
			},
			expected: []expectedVuln{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "issueUrl",
					Metadata: &types.Metadata{
						CVSSv2: types.MetadataCVSSv2{
							Score:               3.5,
							Vectors:             "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ExploitabilityScore: 6.8,
							ImpactScore:         2.9,
						},
						CVSSv3: types.MetadataCVSSv3{
							Score:               6.3,
							Vectors:             "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 1.8,
							ImpactScore:         4.0,
						},
					},
					FixedBy: "1.0.1",
				},
			},
		},
		{
			version: "1.1.0",
			cves: []*validation.CVESchema{
				{
					CVE:         "CVE-2020-1234",
					Description: "test2",
					IssueURL:    "issueUrl",
					URL:         "url",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					Affected: []validation.AffectedSchema{
						{
							Range:   "< 1.1.1",
							FixedBy: "1.1.1",
						},
						{
							Range:   "> 1.1, < 1.2",
							FixedBy: "1.2.0",
						},
						{
							Range:   "> 2.0, < 2.0.0",
							FixedBy: "2.0.0",
						},
					},
				},
				{
					CVE:         "CVE-2020-1235",
					Description: "test2",
					URL:         "url",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					Affected: []validation.AffectedSchema{
						{
							Range:   "< 1.0.0",
							FixedBy: "1.0.0",
						},
					},
				},
				{
					CVE:         "CVE-2020-1236",
					Description: "test3",
					URL:         "url",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					Affected: []validation.AffectedSchema{
						{
							Range:   "< 0.9.0",
							FixedBy: "0.9.0",
						},
						{
							Range:   ">= 1.0, <= 1.0.3",
							FixedBy: "1.0.4",
						},
						{
							Range:   ">= 1.1, < 1.1.2",
							FixedBy: "1.1.3",
						},
						{
							Range:   ">= 1.2, < 2.0.0",
							FixedBy: "2.0.0",
						},
					},
				},
			},
			expected: []expectedVuln{
				{
					Name:        "CVE-2020-1234",
					Description: "test2",
					Link:        "issueUrl",
					Metadata: &types.Metadata{
						CVSSv3: types.MetadataCVSSv3{
							Score:               7.7,
							Vectors:             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore:         4.0,
						},
					},
					FixedBy: "1.1.1",
				},
				{
					Name:        "CVE-2020-1235",
					Description: "test2",
					Link:        "url",
					Metadata: &types.Metadata{
						CVSSv3: types.MetadataCVSSv3{
							Score:               7.7,
							Vectors:             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore:         4.0,
						},
					},
				},
				{
					Name:        "CVE-2020-1236",
					Description: "test3",
					Link:        "url",
					Metadata: &types.Metadata{
						CVSSv3: types.MetadataCVSSv3{
							Score:               7.7,
							Vectors:             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore:         4.0,
						},
					},
					FixedBy: "1.1.3",
				},
			},
		},
		{
			// Potential kubeProxyVersion or kubeletVersion.
			version: "v1.11.0+d4cacc0",
			cves: []*validation.CVESchema{
				{
					CVE:         "CVE-2020-1234",
					Description: "test1",
					IssueURL:    "issueUrl",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV2:  3.5,
							VectorV2: "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
						Kubernetes: &validation.KubernetesSchema{
							ScoreV3:  6.3,
							VectorV3: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					Affected: []validation.AffectedSchema{
						{
							Range:   "<= v1.12.0",
							FixedBy: "v1.12.1+d4cacc0",
						},
					},
				},
			},
			expected: []expectedVuln{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "issueUrl",
					Metadata: &types.Metadata{
						CVSSv2: types.MetadataCVSSv2{
							Score:               3.5,
							Vectors:             "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ExploitabilityScore: 6.8,
							ImpactScore:         2.9,
						},
						CVSSv3: types.MetadataCVSSv3{
							Score:               6.3,
							Vectors:             "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 1.8,
							ImpactScore:         4.0,
						},
					},
					FixedBy: "v1.12.1+d4cacc0",
				},
			},
		},
	}

	for _, testCase := range testCases {
		vulns, err := convertK8sVulnerabilities(testCase.version, testCase.cves)
		assert.NoError(t, err)
		assert.Equal(t, len(testCase.expected), len(vulns))
		for i, vuln := range vulns {
			expected := testCase.expected[i]
			var m types.Metadata
			err := json.Unmarshal(vuln.Metadata, &m)
			require.NoError(t, err)
			assert.Equal(t, expected.Name, vuln.Name)
			assert.Equal(t, expected.Description, vuln.Description)
			assert.Equal(t, expected.Link, vuln.Link)
			assert.Equal(t, expected.Metadata, &m)
			assert.Equal(t, expected.FixedBy, vuln.FixedBy)
		}
	}
}

func TestConvertNVDVulns(t *testing.T) {
	testCases := []struct {
		cveItems []*nvdtoolscache.NVDCVEItemWithFixedIn
		expected []expectedVuln
	}{
		{
			cveItems: []*nvdtoolscache.NVDCVEItemWithFixedIn{
				{
					NVDCVEFeedJSON10DefCVEItem: &schema.NVDCVEFeedJSON10DefCVEItem{
						CVE: &schema.CVEJSON40{
							CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
								ID: "CVE-2020-1234",
							},
							Description: &schema.CVEJSON40Description{
								DescriptionData: []*schema.CVEJSON40LangString{
									{
										Lang:  "en",
										Value: "test1",
									},
								},
							},
						},
						PublishedDate:    "10",
						LastModifiedDate: "11",
						Impact: &schema.NVDCVEFeedJSON10DefImpact{
							BaseMetricV3: &schema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
								CVSSV3: &schema.CVSSV30{
									BaseScore:    7.7,
									VectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
								},
								ExploitabilityScore: 3.1,
								ImpactScore:         4.0,
							},
						},
					},
					FixedIn: "1.3.4",
				},
			},
			expected: []expectedVuln{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1234",
					Metadata: &types.Metadata{
						PublishedDateTime:    "10",
						LastModifiedDateTime: "11",
						CVSSv3: types.MetadataCVSSv3{
							Score:               7.7,
							Vectors:             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore:         4.0,
						},
					},
					FixedBy: "1.3.4",
				},
			},
		},
	}

	for _, testCase := range testCases {
		vulns, err := convertNVDVulns(testCase.cveItems)
		assert.NoError(t, err)
		assert.Equal(t, len(testCase.expected), len(vulns))
		for i, vuln := range vulns {
			expected := testCase.expected[i]
			var m types.Metadata
			err := json.Unmarshal(vuln.Metadata, &m)
			require.NoError(t, err)
			assert.Equal(t, expected.Name, vuln.Name)
			assert.Equal(t, expected.Description, vuln.Description)
			assert.Equal(t, expected.Link, vuln.Link)
			assert.Equal(t, expected.Metadata, &m)
			assert.Equal(t, expected.FixedBy, vuln.FixedBy)
		}
	}
}

func TestConvertVersion(t *testing.T) {
	for _, testCase := range []struct {
		version  string
		expected string
	}{
		{
			version:  "1.0.0",
			expected: "1.0.0",
		},
		{
			version:  "v1.0.0",
			expected: "1.0.0",
		},
		{
			version:  "v1.11.0+d4cacc0",
			expected: "1.11.0",
		},
		{
			version:  "19.3.5",
			expected: "19.3.5",
		},
		{
			version:  "1.11.13-1.rhaos3.11.gitfb88a9c.el7",
			expected: "1.11.13",
		},
		{
			version:  "3.10.0-1127.13.1.el7.x86_64",
			expected: "3.10.0",
		},
		{
			version:  "5.4.0-1027-gke",
			expected: "5.4.0",
		},
		{
			version:  "4.19.112+",
			expected: "4.19.112",
		},
		{
			version:  "v1.17.12-eks-7684af",
			expected: "1.17.12",
		},
		{
			version:  "4.14.203-156.332.amzn2.x86_64",
			expected: "4.14.203",
		},
	} {
		actual, err := truncateVersion(testCase.version)
		assert.NoError(t, err)
		assert.Equal(t, testCase.expected, actual)
	}
}
