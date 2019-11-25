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

type expectedFeature struct {
	name          string
	version       string
	expectedVulns []expectedVuln
}

type singleTestCase struct {
    imageRepo           string
	imageTag            string
	expectedFeatures    []expectedFeature
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

            for _, feat := range scan.GetImage().GetFeatures() {
                for _, vuln := range feat.GetVulnerabilities() {
                    fmt.Println(vuln.GetName(), vuln.GetDescription())
                }
            }
            fmt.Println("DONE PRINTING VULNS FROM SCAN")

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

			for _, expectedVuln := range expectedFeat.expectedVulns {
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
}

func testMultipleFeatureCheck(testCase singleTestCase, t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewScanServiceClient(conn)
	scanResp := scanPublicImage(client, fmt.Sprintf("docker.io/%s:%s", testCase.imageRepo, testCase.imageTag), t)
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

            for _, feat := range scan.GetImage().GetFeatures() {
                for _, vuln := range feat.GetVulnerabilities() {
                    fmt.Println(vuln.GetName(), vuln.GetDescription())
                }
            }
            fmt.Println("DONE PRINTING VULNS FROM SCAN")

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

	featureCounts := make( map[string]int )
	for _, feature := range scan.GetImage().GetFeatures() {
	    featureCounts[feature.GetName()]++
	}

    for feature, count := range featureCounts {
	    t.Run(fmt.Sprintf("%s", feature), func(t *testing.T) {
	        require.Less(t, count, 4)
	    })
	}
}

// This test tests vulnerable images pushed up to docker.io/stackrox/vuln-images.
// Images are pushed from https://github.com/stackrox/vuln-images.
func TestStackroxVulnImages(t *testing.T) {
	for _, testCase := range []singleTestCase{
		{
			imageTag: "django-cve-2019-14235",
			expectedFeatures: []expectedFeature{
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
			expectedFeatures: []expectedFeature{
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
			expectedFeatures: []expectedFeature{
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
	} {
		t.Run(testCase.imageTag, func(t *testing.T) {
			testSingleVulnImage(testCase, t)
		})
	}
}

// This test tests vulnerable images found in public repos.
func TestPublicVulnImages(t *testing.T) {
	for _, testCase := range []singleTestCase{
		{
			imageRepo: "apicurio/apicurio-studio-api",
			imageTag: "latest",
		},
		{
			imageRepo: "codenvy/che-dashboard",
			imageTag: "latest",
		},
		{
			imageRepo: "haxqer/jira",
			imageTag: "latest",
		},
	} {
		t.Run(testCase.imageTag, func(t *testing.T) {
			testMultipleFeatureCheck(testCase, t)
		})
	}
}
