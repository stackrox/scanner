package cpe

import (
	"fmt"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stretchr/testify/assert"
)

func TestGenerateNameKeys(t *testing.T) {
	cases := []struct {
		name      string
		keys      []string
		hasVendor bool
	}{
		{
			name: "",
		},
		{
			name: "name",
			keys: []string{
				"name",
			},
		},
		{
			name: "struts-showcase",
			keys: []string{
				"struts",
				"struts-showcase",
				"struts_showcase",
			},
			hasVendor: true,
		},
		{
			name: "struts2-showcase",
			keys: []string{
				"struts",
				"struts2",
				"struts2-showcase",
				"struts2_showcase",
			},
			hasVendor: true,
		},
		{
			name: "struts-showcase",
			keys: []string{
				"struts-showcase",
				"struts_showcase",
			},
			hasVendor: false,
		},
		{
			name: "struts2-showcase",
			keys: []string{
				"struts2-showcase",
				"struts2_showcase",
			},
			hasVendor: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.ElementsMatch(t, c.keys, generateNameKeys(c.name, c.hasVendor).AsSlice())
		})
	}
}

func TestGetAttributes(t *testing.T) {
	cases := []struct {
		comp               *component.Component
		expectedAttributes []*wfn.Attributes
	}{
		{
			comp: &component.Component{
				Name:    "struts2-showcase",
				Version: "1.3.12",
			},
			expectedAttributes: []*wfn.Attributes{
				{
					Product: "struts2-showcase",
					Version: "1.3.12",
				},
				{
					Product: "struts2-showcase",
					Version: "1\\.3\\.12",
				},
				{
					Product: "struts2_showcase",
					Version: "1.3.12",
				},
				{
					Product: "struts2_showcase",
					Version: "1\\.3\\.12",
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.comp.Name, c.comp.Version), func(t *testing.T) {
			assert.ElementsMatch(t, c.expectedAttributes, getAttributes(c.comp))
		})
	}
}

func newMockCVEFeedVuln(id string) cvefeed.Vuln {
	return &nvd.Vuln{
		CVEItem: &schema.NVDCVEFeedJSON10DefCVEItem{
			CVE: &schema.CVEJSON40{
				CVEDataMeta: &schema.CVEJSON40CVEDataMeta{
					ID: id,
				},
			},
		},
	}
}

func newDatabaseVuln(id string) database.Vulnerability {
	return database.Vulnerability{
		Name:     id,
		Link:     fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id),
		Severity: "",
		Metadata: map[string]interface{}{
			"NVD": &nvdtoolscache.Metadata{},
		},
	}
}

func TestGetFeaturesMapFromMatchResults(t *testing.T) {
	cases := []struct {
		name     string
		matches  []cvefeed.MatchResult
		features []database.FeatureVersion
	}{
		{
			name:    "no matches",
			matches: []cvefeed.MatchResult{},
		},
		{
			name: "one match but not attributes (shouldn't happen)",
			matches: []cvefeed.MatchResult{
				{
					CVE: newMockCVEFeedVuln("cve1"),
				},
			},
		},
		{
			name: "one match",
			matches: []cvefeed.MatchResult{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product",
							Version: "version",
						},
					},
				},
			},
			features: []database.FeatureVersion{
				{
					Feature: database.Feature{
						Name:       "product",
						SourceType: "UnsetSourceType",
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
			},
		},
		{
			name: "one match with two CPEs",
			matches: []cvefeed.MatchResult{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product",
							Version: "version",
						},
						{
							Product: "product2",
							Version: "version2",
						},
					},
				},
			},
			features: []database.FeatureVersion{
				{
					Feature: database.Feature{
						Name:       "product",
						SourceType: "UnsetSourceType",
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
				{
					Feature: database.Feature{
						Name:       "product2",
						SourceType: "UnsetSourceType",
					},
					Version: "version2",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
			},
		},
		{
			name: "two matches with same CPE",
			matches: []cvefeed.MatchResult{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product",
							Version: "version",
						},
					},
				},
				{
					CVE: newMockCVEFeedVuln("cve2"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product",
							Version: "version",
						},
					},
				},
			},
			features: []database.FeatureVersion{
				{
					Feature: database.Feature{
						Name:       "product",
						SourceType: "UnsetSourceType",
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
						newDatabaseVuln("cve2"),
					},
				},
			},
		},
		{
			name: "two matches with different CPE",
			matches: []cvefeed.MatchResult{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product",
							Version: "version",
						},
					},
				},
				{
					CVE: newMockCVEFeedVuln("cve2"),
					CPEs: []*wfn.Attributes{
						{
							Product: "product2",
							Version: "version2",
						},
					},
				},
			},
			features: []database.FeatureVersion{
				{
					Feature: database.Feature{
						Name:       "product",
						SourceType: "UnsetSourceType",
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
				{
					Feature: database.Feature{
						Name:       "product2",
						SourceType: "UnsetSourceType",
					},
					Version: "version2",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve2"),
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matchResults := make([]matchResultWrapper, 0, len(c.matches))
			for _, m := range c.matches {
				matchResults = append(matchResults, matchResultWrapper{
					MatchResult: m,
				})
			}

			features := getFeaturesFromMatchResults("", matchResults)
			assert.ElementsMatch(t, c.features, features)
		})
	}
}
