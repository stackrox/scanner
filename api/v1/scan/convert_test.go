package scan

import (
	"encoding/json"
	"testing"

	"github.com/stackrox/k8s-cves/pkg/validation"
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
	testCases := []struct{
		version  string
		cves     []*validation.CVESchema
		expected []expectedVuln
	}{
		{
			version: "1.0.0",
			cves: []*validation.CVESchema{
				{
					CVE: "CVE-2020-1234",
					Description: "test1",
					IssueURL: "issueUrl",
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
					FixedBy: []string{"1.0.1"},

				},
			},
			expected: []expectedVuln{
				{
					Name: "CVE-2020-1234",
					Description: "test1",
					Link: "issueUrl",
					Metadata: &types.Metadata{
						CVSSv2: types.MetadataCVSSv2{
							Score: 3.5,
							Vectors: "AV:N/AC:M/Au:S/C:P/I:N/A:N",
							ExploitabilityScore: 6.8,
							ImpactScore: 2.9,
						},
						CVSSv3: types.MetadataCVSSv3{
							Score: 6.3,
							Vectors: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 1.8,
							ImpactScore: 4.0,
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
					CVE: "CVE-2020-1234",
					Description: "test2",
					IssueURL: "issueUrl",
					URL: "url",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
					FixedBy: []string{"1.1.1", "1.2.0", "2.0.0"},

				},
				{
					CVE: "CVE-2020-1235",
					Description: "test2",
					URL: "url",
					CVSS: &validation.CVSSSchema{
						NVD: &validation.NVDSchema{
							ScoreV3:  7.7,
							VectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
						},
					},
				},
			},
			expected: []expectedVuln{
				{
					Name: "CVE-2020-1234",
					Description: "test2",
					Link: "issueUrl",
					Metadata: &types.Metadata{
						CVSSv3: types.MetadataCVSSv3{
							Score: 7.7,
							Vectors: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore: 4.0,
						},
					},
					FixedBy: "1.1.1",
				},
				{
					Name: "CVE-2020-1235",
					Description: "test2",
					Link: "url",
					Metadata: &types.Metadata{
						CVSSv3: types.MetadataCVSSv3{
							Score: 7.7,
							Vectors: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
							ExploitabilityScore: 3.1,
							ImpactScore: 4.0,
						},
					},
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
