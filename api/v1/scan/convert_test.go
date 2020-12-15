package scan

import (
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stretchr/testify/assert"
)

func TestConvertK8sVulnerabilities(t *testing.T) {
	testCases := []struct {
		version  string
		cves     []*validation.CVESchema
		expected []*v1.Vulnerability
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
			expected: []*v1.Vulnerability{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "issueUrl",
					MetadataV2: &v1.Metadata{
						CvssV2: &v1.CVSSMetadata{
							Score:               3.5,
							Vector:              "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ExploitabilityScore: 6.8,
							ImpactScore:         2.9,
						},
						CvssV3: &v1.CVSSMetadata{
							Score:               6.3,
							Vector:              "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
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
			expected: []*v1.Vulnerability{
				{
					Name:        "CVE-2020-1234",
					Description: "test2",
					Link:        "issueUrl",
					MetadataV2: &v1.Metadata{
						CvssV3: &v1.CVSSMetadata{
							Score:               7.7,
							Vector:              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
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
					MetadataV2: &v1.Metadata{
						CvssV3: &v1.CVSSMetadata{
							Score:               7.7,
							Vector:              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore:         4.0,
						},
					},
				},
				{
					Name:        "CVE-2020-1236",
					Description: "test3",
					Link:        "url",
					MetadataV2: &v1.Metadata{
						CvssV3: &v1.CVSSMetadata{
							Score:               7.7,
							Vector:              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
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
			expected: []*v1.Vulnerability{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "issueUrl",
					MetadataV2: &v1.Metadata{
						CvssV2: &v1.CVSSMetadata{
							Score:               3.5,
							Vector:              "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ExploitabilityScore: 6.8,
							ImpactScore:         2.9,
						},
						CvssV3: &v1.CVSSMetadata{
							Score:               6.3,
							Vector:              "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
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
		assert.Len(t, testCase.expected, len(vulns))
		assert.ElementsMatch(t, testCase.expected, vulns)
	}
}

func TestConvertNVDVulns(t *testing.T) {
	testCases := []struct {
		cveItems []*nvdtoolscache.NVDCVEItemWithFixedIn
		expected []*v1.Vulnerability
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
			expected: []*v1.Vulnerability{
				{
					Name:        "CVE-2020-1234",
					Description: "test1",
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1234",
					MetadataV2: &v1.Metadata{
						PublishedDateTime:    "10",
						LastModifiedDateTime: "11",
						CvssV3: &v1.CVSSMetadata{
							Score:               7.7,
							Vector:              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
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
		assert.Len(t, testCase.expected, len(vulns))
		assert.Equal(t, testCase.expected, vulns)
	}
}
