package nvd

import (
	"testing"

	"github.com/stackrox/scanner/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNVDJava(t *testing.T) {
	nvd, err := NewNVD("./testdata/nvdcve-1.1-2017.json")
	require.NoError(t, err)

	cases := []struct{
		component *types.Component
		expectedVulns []string
	}{
		{
			component: &types.Component{
				Name:        "struts",
				Version:     "2.3.12",
				Type:        types.JAR,
				JavaPackage: &types.JavaPackage{
					ImplementationVersion: "2.3.12",
					Location:              "",
					MavenVersion:          "2.3.12",
					Name:                  "struts",
					Origin:                "org.apache.struts",
					SpecificationVersion:  "2.3.12",
				},
			},
			expectedVulns: []string {
				"CVE-2017-9804",
				"CVE-2017-9805",
				"CVE-2017-12611",
				"CVE-2017-5638",
				"CVE-2017-9787",
				"CVE-2017-9793",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.component.JavaPackage.Name, func(t *testing.T) {
			assert.ElementsMatch(t, c.expectedVulns, nvd.EvaluateForVulns(c.component))
		})
	}
}