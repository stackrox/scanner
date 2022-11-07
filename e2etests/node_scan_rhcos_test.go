//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"testing"

	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var libksbaVuln = &v1.Vulnerability{
	Name:        "RHSA-2022:7089",
	Description: "KSBA (pronounced Kasbah) is a library to make X.509 certificates as well as the CMS easily accessible by other applications.  Both specifications are building blocks of S/MIME and TLS.\n\nSecurity Fix(es):\n\n* libksba: integer overflow may lead to remote code execution (CVE-2022-3515)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.",
	Link:        "https://access.redhat.com/errata/RHSA-2022:7089",
	MetadataV2: &v1.Metadata{
		PublishedDateTime:    "2022-10-24T00:00Z",
		LastModifiedDateTime: "",
		CvssV2:               nil,
		CvssV3: &v1.CVSSMetadata{
			Score:               8.1,
			Vector:              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			ExploitabilityScore: 2.2,
			ImpactScore:         5.9,
		},
	},
	FixedBy:  "0:1.3.5-8.el8_6",
	Severity: "Important",
}

func TestGRPCGetRHCOSNodeVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewNodeScanServiceClient(conn)

	cases := []struct {
		request          *v1.GetNodeVulnerabilitiesRequest
		responseContains *v1.GetNodeVulnerabilitiesResponse
	}{
		{
			request: &v1.GetNodeVulnerabilitiesRequest{
				OsImage:          "Ubuntu 20.04.1 LTS",
				KernelVersion:    "0.0.1",
				KubeletVersion:   "0.0.1",
				KubeproxyVersion: "0.0.1",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "docker",
					Version: "0.0.1",
				},
				NodeInventory: &v1.Components{
					Namespace: "Red Hat CoreOS",
					RhelComponents: []*v1.RHELComponent{
						{
							Id:        int64(2),
							Name:      "libksba",
							Namespace: "rhel:8",
							Version:   "1.3.5-7.el8",
							Arch:      "x86_64",
							Module:    "",
							// From: https://www.redhat.com/security/data/metrics/repository-to-cpe.json
							// "rhel-8-for-x86_64-appstream-rpms": {"cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream"]},
							// "rhel-8-for-x86_64-baseos-rpms": {"cpes": ["cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:rhel:8.3::baseos"]}
							Cpes: []string{
								"cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream",
								"cpe:/a:redhat:enterprise_linux:8::baseos", "cpe:/a:redhat:rhel:8.3::baseos",
							},
							AddedBy: "",
						},
					},
					LanguageComponents: nil,
				},
			},
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				InventoryFeatures: []*v1.Feature{
					{
						Name:            "libksba",
						Version:         "1.3.5-7.el8.x86_64",
						Vulnerabilities: []*v1.Vulnerability{libksbaVuln},
					},
				},
			},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			c := c
			resp, err := client.GetNodeVulnerabilities(context.Background(), c.request)
			require.NoError(t, err)
			for _, expectedFeat := range c.responseContains.InventoryFeatures {
				found := false
				for _, gotFeat := range resp.InventoryFeatures {
					if expectedFeat.GetName() == gotFeat.GetName() && expectedFeat.GetVersion() == gotFeat.GetVersion() {
						found = true
						assert.NotNil(t, gotFeat)
						assert.NotNil(t, gotFeat.Vulnerabilities, "Expected to find vulnerabilities for %s:%s", expectedFeat.GetName(), expectedFeat.GetVersion())
						t.Logf("gotFeat.InventoryFeatures: %+v\n", resp.InventoryFeatures)
						assertContainsVuln(t, gotFeat.Vulnerabilities, expectedFeat.Vulnerabilities)
					} else {
						t.Logf("skipping feat found in the reply '%s:%s' - no match", gotFeat.GetName(), gotFeat.GetVersion())
					}
				}
				assert.Truef(t, found, "expected feat '%s:%s' in the reply, but got none", expectedFeat.GetName(), expectedFeat.GetVersion())
			}
			assert.Equal(t, c.responseContains.Notes, resp.Notes)
		})
	}
}

func assertContainsVuln(t *testing.T, foundVulns, expectedContains []*v1.Vulnerability) {
	// Prune last modified time
	for _, v := range foundVulns {
		v.MetadataV2.LastModifiedDateTime = ""
	}
	if expectedContains != nil {
		for _, contains := range expectedContains {
			contains.MetadataV2.LastModifiedDateTime = ""
			if !assert.Contains(t, foundVulns, contains) {
				fmt.Printf("Found vulns: %v\n", foundVulns)
				fmt.Printf("Expected vuln: %v\n", contains)
			}
		}
	}
}
