//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
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
	image            string
	expectedFeatures []feature
	unexpectedVulns  []feature
}

func testSingleVulnImage(testCase singleTestCase, t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewImageScanServiceClient(conn)
	var scanResp *v1.ScanImageResponse
	if strings.HasPrefix(testCase.image, "quay.io") {
		scanResp = scanQuayStackRoxImage(client, testCase.image, false, t)
	} else if strings.HasPrefix(testCase.image, "gcr.io") {
		scanResp = scanGCRImage(client, testCase.image, t)
	} else {
		fmt.Printf("no scan method for image: %v\n", testCase.image)
		t.FailNow()
	}
	scan, err := client.GetImageScan(context.Background(), &v1.GetImageScanRequest{
		ImageSpec: scanResp.GetImage(),
	})
	require.NoError(t, err)

	// If the test failed, print helpful debug information.
	defer func() {
		if t.Failed() {
			fmt.Printf("PRINTING COMPONENTS FROM SCAN OF %s\n", testCase.image)
			for _, feat := range scan.GetImage().GetFeatures() {
				fmt.Println(feat.GetName(), feat.GetVersion())
			}
			fmt.Printf("DONE PRINTING COMPONENTS FROM SCAN OF %s\n", testCase.image)

			componentsMap, err := client.GetLanguageLevelComponents(context.Background(), &v1.GetLanguageLevelComponentsRequest{
				ImageSpec: scanResp.GetImage(),
			})
			require.NoError(t, err)
			fmt.Printf("PRINTING LANGUAGE LEVEL COMPONENTS OF %s\n", testCase.image)
			for _, components := range componentsMap.GetLayerToComponents() {
				for _, component := range components.GetComponents() {
					fmt.Println(component.GetName(), component.GetVersion(), component.GetLocation())
				}
			}
			fmt.Printf("DONE PRINTING LANGUAGE LEVEL COMPONENTS OF %s\n", testCase.image)
		}
	}()
	for _, expectedFeat := range testCase.expectedFeatures {
		t.Run(fmt.Sprintf("%s/%s", expectedFeat.name, expectedFeat.version), func(t *testing.T) {
			matchingIdx := slices.IndexFunc(scan.GetImage().GetFeatures(), func(feature *v1.Feature) bool {
				return feature.GetName() == expectedFeat.name && feature.GetVersion() == expectedFeat.version
			})
			require.NotEqual(t, -1, matchingIdx, "Did not find expected feature %s:%s", expectedFeat.name, expectedFeat.version)
			matchingFeature := scan.GetImage().GetFeatures()[matchingIdx]

			for _, expectedVuln := range expectedFeat.vulns {
				matchingIdx := slices.IndexFunc(matchingFeature.GetVulnerabilities(), func(v *v1.Vulnerability) bool {
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
			matchingIdx := slices.IndexFunc(scan.GetImage().GetFeatures(), func(feature *v1.Feature) bool {
				return feature.GetName() == unexpectedFeature.name && feature.GetVersion() == unexpectedFeature.version
			})
			if matchingIdx != -1 {
				matchingFeature := scan.GetImage().GetFeatures()[matchingIdx]
				for _, unexpectedVuln := range unexpectedFeature.vulns {
					matchingIdx := slices.IndexFunc(matchingFeature.GetVulnerabilities(), func(v *v1.Vulnerability) bool {
						return v.GetName() == unexpectedVuln.name
					})
					assert.Equal(t, -1, matchingIdx, "Vuln %s not found", unexpectedVuln)
				}
			}
		})
	}
}

// This test tests vulnerable images pushed up to quay.io/rhacs-eng/qa.
// Images are pushed from https://github.com/stackrox/vuln-images.
func TestStackroxVulnImages(t *testing.T) {
	for _, testCase := range []singleTestCase{
		{
			image: "quay.io/rhacs-eng/qa:django-cve-2019-14235",
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
			image: "quay.io/rhacs-eng/qa:lodash-cve-2019-1010266",
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
			image: "quay.io/rhacs-eng/qa:rails-cve-2016-2098",
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
			image: "quay.io/rhacs-eng/qa:customerssh",
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
			image: "quay.io/rhacs-eng/qa:appdynamics",
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
			image: "quay.io/rhacs-eng/qa:zookeeper",
			expectedFeatures: []feature{
				{"zookeeper", "3.4.13", []expectedVuln{
					{name: "CVE-2019-0201", fixedBy: ""},
				},
				},
			},
		},
		{
			// docker.io/library/cassandra:latest
			image: "quay.io/rhacs-eng/qa:cassandra",
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
			image: "quay.io/rhacs-eng/qa:ignite",
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
		{
			image: "quay.io/rhacs-eng/qa:drools-debian",
			expectedFeatures: []feature{
				{"drools", "6.4.0.final", []expectedVuln{
					{name: "CVE-2021-41411", fixedBy: ""},
				},
				},
			},
		},
		{
			image: "quay.io/rhacs-eng/qa:drools-ubi-minimal",
			expectedFeatures: []feature{
				{"drools", "6.4.0.final", []expectedVuln{
					{name: "CVE-2021-41411", fixedBy: ""},
				},
				},
			},
		},
	} {
		t.Run(testCase.image, func(t *testing.T) {
			testSingleVulnImage(testCase, t)
		})
	}
}

// This test checks images from gcr.io/distroless
func TestDistrolessVulnImages(t *testing.T) {
	for _, testCase := range []singleTestCase{
		{
			image: "gcr.io/distroless/base@sha256:8d58596f5181f95d908d7f8318f8e27bc394164491bd0aa53c2f284480fd8f8b",
			expectedFeatures: []feature{
				{"openssl", "1.1.0l-1~deb9u1", []expectedVuln{
					{name: "CVE-2007-6755"},
					{name: "CVE-2010-0928"},
					{name: "CVE-2019-1551"},
				},
				},
				{"glibc", "2.24-11+deb9u4", []expectedVuln{
					{name: "CVE-2019-9192"},
					{name: "CVE-2019-6488"},
					{name: "CVE-2018-6551"},
					{name: "CVE-2020-10029"},
					{name: "CVE-2019-1010023"},
					{name: "CVE-2020-1752"},
					{name: "CVE-2020-6096"},
					{name: "CVE-2009-5155"},
					{name: "CVE-2010-4756"},
					{name: "CVE-2016-10739"},
					{name: "CVE-2019-1010025"},
					{name: "CVE-2017-12132"},
					{name: "CVE-2018-20796"},
					{name: "CVE-2018-1000001"},
					{name: "CVE-2020-1751"},
					{name: "CVE-2019-19126"},
					{name: "CVE-2019-7309"},
					{name: "CVE-2019-1010024"},
					{name: "CVE-2018-6485"},
					{name: "CVE-2019-9169"},
					{name: "CVE-2015-8985"},
					{name: "CVE-2016-10228"},
					{name: "CVE-2019-1010022"},
				},
				},
			},
		},
		{
			image: "gcr.io/distroless/java-debian10@sha256:6fa3088bb0b2df2419dda9808cdf90d706ff190cff17c2a68397ac7765b3098f",
			expectedFeatures: []feature{
				{"openjdk-11", "11.0.9+11-1~deb10u1", []expectedVuln{}},
				{"openssl", "1.1.1d-0+deb10u3", []expectedVuln{
					{name: "CVE-2020-1971"},
					{name: "CVE-2021-23841"},
				}},
			},
		},
		{
			image: "gcr.io/distroless/python2.7@sha256:6d3895c4a1629ac99e73c7dc9cbe0ad8cb213d6cdebf3e835c2c388fc5aab1b2",
			expectedFeatures: []feature{
				{"python2.7", "2.7.13-2+deb9u4", []expectedVuln{
					{name: "CVE-2013-7040"},
					{name: "CVE-2019-16935"},
					{name: "CVE-2019-18348"},
					{name: "CVE-2019-9674"},
					{name: "CVE-2017-17522"},
					{name: "CVE-2020-8492"},
					{name: "CVE-2018-1000030"},
				},
				},
			},
		},
		{
			image: "gcr.io/distroless/python3@sha256:8e74b6697d0a741a5d1bb7366260f48721783f71e01d800c13cd2392586639f3",
			expectedFeatures: []feature{
				{"python3.5", "3.5.3-1+deb9u2", []expectedVuln{
					{name: "CVE-2020-26116"},
					{name: "CVE-2019-20907"},
					{name: "CVE-2019-9674"},
					{name: "CVE-2017-17522"},
				},
				},
			},
		},
		{
			image: "gcr.io/distroless/static@sha256:f4050ae771417b5a91d3906d9a9d2e7d04ccf1096d8cf88812ff15097ffde67a",
			expectedFeatures: []feature{
				{"netbase", "5.4", []expectedVuln{}},
				{"tzdata", "2020a-0+deb9u1", []expectedVuln{}},
				{"base-files", "9.9+deb9u13", []expectedVuln{}},
			},
		},
	} {
		t.Run(testCase.image, func(t *testing.T) {
			testSingleVulnImage(testCase, t)
		})
	}
}
