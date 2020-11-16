package cpe

import (
	"fmt"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestGetAttributeFuncs(t *testing.T) {
	assert.Equal(t, int(component.SentinelEndSourceType-component.UnsetSourceType-1), len(attributeGetter))
}

func TestGetAttributes(t *testing.T) {
	cases := []struct {
		comp               *component.Component
		expectedAttributes []*wfn.Attributes
	}{
		{
			comp: &component.Component{
				Name:            "struts2-showcase",
				Version:         "1.3.12",
				SourceType:      component.JavaSourceType,
				JavaPkgMetadata: &component.JavaPkgMetadata{},
			},
			expectedAttributes: []*wfn.Attributes{
				{
					Vendor:  "apache",
					Product: `struts2\-showcase`,
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: `struts2\-showcase`,
					Version: `1\.3\.12`,
				},
				{
					Vendor:  "apache",
					Product: "struts2_showcase",
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2_showcase",
					Version: `1\.3\.12`,
				},
			},
		},
		{
			comp: &component.Component{
				Name:            "struts2-all",
				Version:         "1.3.12",
				SourceType:      component.JavaSourceType,
				JavaPkgMetadata: &component.JavaPkgMetadata{},
			},
			expectedAttributes: []*wfn.Attributes{
				{
					Vendor:  "apache",
					Product: "struts2\\-all",
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2\\-all",
					Version: "1\\.3\\.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2_all",
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2_all",
					Version: "1\\.3\\.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2",
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: "struts2",
					Version: "1\\.3\\.12",
				},
				{
					Vendor:  "apache",
					Product: "struts",
					Version: "1.3.12",
				},
				{
					Vendor:  "apache",
					Product: "struts",
					Version: "1\\.3\\.12",
				},
			},
		},
		{
			comp: &component.Component{
				Name:       "Microsoft.AspNetCore.App",
				Version:    "3.1.9",
				SourceType: component.DotNetCoreRuntimeSourceType,
			},
			expectedAttributes: []*wfn.Attributes{
				{
					Vendor:  "microsoft",
					Product: "microsoft.aspnetcore.app",
					Version: "3.1.9",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft.aspnetcore.app",
					Version: "3\\.1\\.9",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft\\.aspnetcore\\.app",
					Version: "3.1.9",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft\\.aspnetcore\\.app",
					Version: "3\\.1\\.9",
				},
			},
		},
		{
			comp: &component.Component{
				Name:       "Microsoft.NETCore.App",
				Version:    "3.1.8",
				SourceType: component.DotNetCoreRuntimeSourceType,
			},
			expectedAttributes: []*wfn.Attributes{
				{
					Vendor:  "microsoft",
					Product: "microsoft.netcore.app",
					Version: "3.1.8",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft.netcore.app",
					Version: "3\\.1\\.8",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft\\.netcore\\.app",
					Version: "3.1.8",
				},
				{
					Vendor:  "microsoft",
					Product: "microsoft\\.netcore\\.app",
					Version: "3\\.1\\.8",
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
			"NVD": &types.Metadata{},
		},
	}
}

func newComponent() *component.Component {
	return &component.Component{
		SourceType: component.JavaSourceType,
	}
}

func TestGetFeaturesMapFromMatchResults(t *testing.T) {
	cases := []struct {
		name     string
		matches  []match.Result
		features []database.FeatureVersion
	}{
		{
			name:    "no matches",
			matches: []match.Result{},
		},
		{
			name: "one match but not attributes (shouldn't happen)",
			matches: []match.Result{
				{
					CVE: newMockCVEFeedVuln("cve1"),
				},
			},
			features: []database.FeatureVersion{},
		},
		{
			name: "one match",
			matches: []match.Result{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPE: wfn.AttributesWithFixedIn{
						Attributes: &wfn.Attributes{
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
						SourceType: component.JavaSourceType.String(),
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
			},
		},
		{
			name: "two matches with same CPE",
			matches: []match.Result{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPE: wfn.AttributesWithFixedIn{
						Attributes: &wfn.Attributes{
							Product: "product",
							Version: "version",
						},
					},
				},
				{
					CVE: newMockCVEFeedVuln("cve2"),
					CPE: wfn.AttributesWithFixedIn{
						Attributes: &wfn.Attributes{
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
						SourceType: component.JavaSourceType.String(),
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
			matches: []match.Result{
				{
					CVE: newMockCVEFeedVuln("cve1"),
					CPE: wfn.AttributesWithFixedIn{
						Attributes: &wfn.Attributes{
							Product: "product",
							Version: "version",
						},
					},
				},
				{
					CVE: newMockCVEFeedVuln("cve2"),
					CPE: wfn.AttributesWithFixedIn{
						Attributes: &wfn.Attributes{
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
						SourceType: component.JavaSourceType.String(),
					},
					Version: "version",
					AffectedBy: []database.Vulnerability{
						newDatabaseVuln("cve1"),
					},
				},
				{
					Feature: database.Feature{
						Name:       "product2",
						SourceType: component.JavaSourceType.String(),
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
			for i := range c.matches {
				c.matches[i].Component = newComponent()
				c.matches[i].Vuln = types.NewVulnerability(c.matches[i].CVE.(*nvd.Vuln).CVEItem)
			}
			features := getFeaturesFromMatchResults("", c.matches)
			assert.ElementsMatch(t, c.features, features)
		})
	}
}
