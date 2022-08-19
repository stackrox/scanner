package convert

import (
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/assert"
)

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
					FixedBy:  "1.3.4",
					Severity: "Moderate",
				},
			},
		},
	}

	for _, testCase := range testCases {
		vulns, err := NVDVulns(testCase.cveItems)
		assert.NoError(t, err)
		assert.Len(t, testCase.expected, len(vulns))
		assert.Equal(t, testCase.expected, vulns)
	}
}
