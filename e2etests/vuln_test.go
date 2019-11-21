// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"testing"

	"github.com/stackrox/rox/pkg/sliceutils"
	v1 "github.com/stackrox/scanner/generated/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedVuln struct {
	name, fixedBy string
}

type feature struct {
	name    string
	version string
	vulns   []expectedVuln
}

type singleTestCase struct {
	imageTag         string
	expectedFeatures []feature
	unexpectedVulns  []feature
}

func testSingleVulnImage(testCase singleTestCase, t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanDockerIOStackRoxImage(client, fmt.Sprintf("docker.io/stackrox/vuln-images:%s", testCase.imageTag), t)
	scan, err := client.GetScan(context.Background(), &v1.GetScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)

	// If the test failed, print helpful debug information.
	defer func() {
		if t.Failed() {
			for _, feat := range scan.GetImage().GetFeatures() {
				fmt.Println(feat.GetName(), feat.GetVersion())
			}
			fmt.Println("DONE PRINTING COMPONENTS FROM SCAN")

			componentsMap, err := client.GetLanguageLevelComponents(context.Background(), &v1.GetLanguageLevelComponentsRequest{
				ImageSpec: scanResp.GetImage(),
			})
			require.NoError(t, err)
			for _, components := range componentsMap.GetLayerToComponents() {
				for _, component := range components.GetComponents() {
					fmt.Println(component.GetName(), component.GetVersion(), component.GetLocation())
				}
			}
			fmt.Println("DONE PRINTING LANGUAGE LEVEL COMPONENTS")
		}
	}()
	for _, expectedFeat := range testCase.expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", expectedFeat.name, expectedFeat.version), func(t *testing.T) {
			matchingIdx := sliceutils.FindMatching(scan.GetImage().GetFeatures(), func(feature *v1.Feature) bool {
				return feature.GetName() == expectedFeat.name && feature.GetVersion() == expectedFeat.version
			})
			require.NotEqual(t, -1, matchingIdx)
			matchingFeature := scan.GetImage().GetFeatures()[matchingIdx]

			for _, expectedVuln := range expectedFeat.vulns {
				matchingIdx := sliceutils.FindMatching(matchingFeature.GetVulnerabilities(), func(v *v1.Vulnerability) bool {
					if expectedVuln.fixedBy == "" {
						return v.GetName() == expectedVuln.name
					}
					return v.GetName() == expectedVuln.name && v.GetFixedBy() == expectedVuln.fixedBy
				})
				assert.NotEqual(t, -1, matchingIdx, "Vuln %s not found", expectedVuln)
			}
		})
	}
	for _, unexpectedFeature := range testCase.unexpectedVulns {
		t.Run(fmt.Sprintf("unexpected/%s/%s", unexpectedFeature.name, unexpectedFeature.version), func(t *testing.T) {
			matchingIdx := sliceutils.FindMatching(scan.GetImage().GetFeatures(), func(feature *v1.Feature) bool {
				return feature.GetName() == unexpectedFeature.name && feature.GetVersion() == unexpectedFeature.version
			})
			if matchingIdx != -1 {
				matchingFeature := scan.GetImage().GetFeatures()[matchingIdx]
				for _, unexpectedVuln := range unexpectedFeature.vulns {
					matchingIdx := sliceutils.FindMatching(matchingFeature.GetVulnerabilities(), func(v *v1.Vulnerability) bool {
						return v.GetName() == unexpectedVuln.name
					})
					assert.Equal(t, -1, matchingIdx, "Vuln %s not found", unexpectedVuln)
				}
			}
		})
	}
}

// This test tests vulnerable images pushed up to docker.io/stackrox/vuln-images.
// Images are pushed from https://github.com/stackrox/vuln-images.
func TestStackroxVulnImages(t *testing.T) {
	for _, testCase := range []singleTestCase{
		{
			imageTag: "django-cve-2019-14235",
			expectedFeatures: []feature{
				{"django", "2.1", []expectedVuln{
					{name: "CVE-2018-16984", fixedBy: "2.1.2"},
					{name: "CVE-2019-12308", fixedBy: "2.1.9"},
					{name: "CVE-2019-12781", fixedBy: "2.1.10"},
					{name: "CVE-2019-3498", fixedBy: "2.1.5"},
					{name: "CVE-2019-14232", fixedBy: "2.1.11"},
					{name: "CVE-2019-14233", fixedBy: "2.1.11"},
					{name: "CVE-2019-14234", fixedBy: "2.1.11"},
					{name: "CVE-2019-14235", fixedBy: "2.1.11"},
				},
				},
			},
		},
		{
			imageTag: "lodash-cve-2019-1010266",
			expectedFeatures: []feature{
				{"lodash", "4.17.10", []expectedVuln{
					{name: "CVE-2019-10744", fixedBy: "4.17.12"},
					{name: "CVE-2018-16487", fixedBy: "4.17.11"},
					{name: "CVE-2019-1010266", fixedBy: "4.17.11"},
				},
				},
			},
		},
		{
			imageTag: "rails-cve-2016-2098",
			expectedFeatures: []feature{
				{"rails", "4.2.5.1", []expectedVuln{
					{name: "CVE-2016-2098"},
					{name: "CVE-2016-6316"},
					{name: "CVE-2016-6317"},
					{name: "CVE-2018-16476", fixedBy: "4.2.11"},
					{name: "CVE-2019-5418", fixedBy: "4.2.11.1"},
					{name: "CVE-2019-5419", fixedBy: "4.2.11.1"},
					{name: "CVE-2019-5420", fixedBy: "5.2.2.1"},
				},
				},
			},
		},
		{
			// docker.io/1and1internet/ubuntu-16-customerssh:latest
			imageTag: "customerssh",
			expectedFeatures: []feature{
				{"debug", "2.2.0", []expectedVuln{
					{name: "CVE-2017-16137", fixedBy: "2.6.9"},
				},
				},
			},
			unexpectedVulns: []feature{
				{"editor", "1.0.0", []expectedVuln{
					{name: "CVE-2015-0903"},
				},
				},
			},
		},
		{
			// appddemo/appdynamics-monitor@sha256:145ecc6c8b3a846b2c078806dbfae74b1c7dfdcde6f7931321e3763a5f898109
			imageTag: "appdynamics",
			expectedFeatures: []feature{
				{"commons_beanutils", "1.9.2", []expectedVuln{
					{name: "CVE-2019-10086", fixedBy: ""},
				},
				},
				{"commons_fileupload", "1.3.2", []expectedVuln{
					{name: "CVE-2016-1000031", fixedBy: ""},
				},
				},
				{"guava", "18.0", []expectedVuln{
					{name: "CVE-2018-10237", fixedBy: "24.1.1"},
				},
				},
			},
			unexpectedVulns: []feature{
				{"mail", "1.4", []expectedVuln{
					{name: "CVE-2017-15806"},
					{name: "CVE-2011-0739"},
					{name: "CVE-2015-9097"},
					{name: "CVE-2015-2512"},
				},
				},
			},
		},
		{
			// docker.io/31z4/zookeeper:latest@sha256:b8b94423656f32d19a2a6ee29ceae409c82cca106ee89469c4498ceaaf3007f5
			imageTag: "zookeeper",
			expectedFeatures: []feature{
				{"zookeeper", "3.4.13", []expectedVuln{
					{name: "CVE-2019-0201", fixedBy: ""},
				},
				},
			},
		},
		{
			// docker.io/library/cassandra:latest
			imageTag: "cassandra",
			expectedFeatures: []feature{
				{"logback", "1.1.3", []expectedVuln{
					{name: "CVE-2017-5929", fixedBy: ""},
				},
				},
			},
			unexpectedVulns: []feature{
				{"slingshot", "0.10.3", []expectedVuln{
					{name: "CVE-2015-5711"},
				},
				},
			},
		},
		{
			// docker.io/apacheignite/ignite:latest
			imageTag: "ignite",
			expectedFeatures: []feature{
				{"camel", "2.22.0", []expectedVuln{
					{name: "CVE-2019-0194", fixedBy: ""},
				},
				},
			},
			unexpectedVulns: []feature{
				{"docker", "1.9.3", []expectedVuln{
					{name: "CVE-2019-5736"},
				},
				},
				{"mesos", "1.5.0", []expectedVuln{
					{name: "CVE-2018-11793"},
				},
				},
			},
		},
	} {
		t.Run(testCase.imageTag, func(t *testing.T) {
			testSingleVulnImage(testCase, t)
		})
	}
}
