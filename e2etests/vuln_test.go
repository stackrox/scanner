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

type expectedFeature struct {
	name          string
	version       string
	expectedVulns []string
}

type singleTestCase struct {
	imageTag         string
	expectedFeatures []expectedFeature
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

			for _, expectedVuln := range expectedFeat.expectedVulns {
				matchingIdx := sliceutils.FindMatching(matchingFeature.GetVulnerabilities(), func(v *v1.Vulnerability) bool {
					return v.GetName() == expectedVuln
				})
				assert.NotEqual(t, -1, matchingIdx, "Vuln %s not found", expectedVuln)
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
			expectedFeatures: []expectedFeature{
				{"django", "2.1", []string{
					"CVE-2018-16984",
					"CVE-2019-12308",
					"CVE-2019-12781",
					"CVE-2019-3498",
					"CVE-2019-14232",
					"CVE-2019-14233",
					"CVE-2019-14234",
					"CVE-2019-14235",
				},
				},
			},
		},
		{
			imageTag: "lodash-cve-2019-1010266",
			expectedFeatures: []expectedFeature{
				{"lodash", "4.17.10", []string{
					"CVE-2019-10744",
					"CVE-2018-16487",
					"CVE-2019-1010266",
				},
				},
			},
		},
		{
			imageTag: "rails-cve-2016-2098",
			expectedFeatures: []expectedFeature{
				{"rails", "4.2.5.1", []string{
					// TODO: Uncomment these after fixing the matching.
					// "CVE-2016-2098",
					// "CVE-2016-6316",
					// "CVE-2016-6317",
					"CVE-2018-16476",
					// "CVE-2019-5418",
					// "CVE-2019-5419",
					// "CVE-2019-5420",
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
