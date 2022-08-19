package convert

import (
	"testing"

	"github.com/stackrox/k8s-cves/pkg/validation"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
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
					FixedBy:  "1.0.1",
					Severity: "Moderate",
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
					FixedBy:  "1.1.1",
					Severity: "Important",
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
					Severity: "Important",
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
					FixedBy:  "1.1.3",
					Severity: "Important",
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
					FixedBy:  "v1.12.1+d4cacc0",
					Severity: "Moderate",
				},
			},
		},
	}

	for _, testCase := range testCases {
		vulns, err := K8sVulnerabilities(testCase.version, testCase.cves)
		assert.NoError(t, err)
		assert.Len(t, testCase.expected, len(vulns))
		assert.ElementsMatch(t, testCase.expected, vulns)
	}
}
