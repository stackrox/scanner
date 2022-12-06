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

// vulnLibksba is an example of a fixable vulnerability
var vulnLibksba = &v1.Vulnerability{
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

// vulnTar is an example of a non-fixable vulnerability
var vulnTar = &v1.Vulnerability{
	Name:        "CVE-2005-2541",
	Description: "DOCUMENTATION: The MITRE CVE dictionary describes this issue as: Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges. \n            STATEMENT: This CVE was assigned to what is the documented and expected behaviour of tar.  There are currently no plans to change tar behaviour to strip setuid and setgid bits when extracting archives.",
	Link:        "https://access.redhat.com/security/cve/CVE-2005-2541",
	MetadataV2: &v1.Metadata{
		CvssV2: nil,
		CvssV3: &v1.CVSSMetadata{
			Score:               7,
			Vector:              "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
			ExploitabilityScore: 1,
			ImpactScore:         5.9,
		},
	},
	FixedBy:  "",
	Severity: "Moderate",
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
				OsImage:          "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",
				KernelVersion:    "0.0.1",
				KubeletVersion:   "0.0.1",
				KubeproxyVersion: "0.0.1",
				Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
					Name:    "docker",
					Version: "0.0.1",
				},
				NodeInventory: &v1.Components{
					Namespace: "Namespace-Name",
					RhelComponents: []*v1.RHELComponent{
						{
							Id:        int64(1),
							Name:      "libksba",
							Namespace: "rhel:8",
							Version:   "1.3.5-7.el8",
							Arch:      "x86_64",
							Module:    "", // must be empty, otherwise scanner does not return any vulns
							// From: https://www.redhat.com/security/data/metrics/repository-to-cpe.json
							// "rhel-8-for-x86_64-appstream-rpms": {"cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream"]},
							// "rhel-8-for-x86_64-baseos-rpms": {"cpes": ["cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:rhel:8.3::baseos"]}
							Cpes: []string{
								"cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream",
								"cpe:/a:redhat:enterprise_linux:8::baseos", "cpe:/a:redhat:rhel:8.3::baseos",
							},
							AddedBy: "",
						},
						{
							Id:        int64(2),
							Name:      "tar",
							Namespace: "rhel:8",
							Version:   "1.27.1.el8",
							Arch:      "x86_64",
							Module:    "",
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
						Vulnerabilities: []*v1.Vulnerability{vulnLibksba},
					},
					{
						Name:            "tar",
						Version:         "1.27.1.el8.x86_64",
						Vulnerabilities: []*v1.Vulnerability{vulnTar},
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
			for _, expectedFeat := range c.responseContains.GetInventoryFeatures() {
				var found bool
				for _, gotFeat := range resp.GetInventoryFeatures() {
					if expectedFeat.GetName() == gotFeat.GetName() && expectedFeat.GetVersion() == gotFeat.GetVersion() {
						found = true
						assert.NotNil(t, gotFeat)
						assert.NotNil(t, gotFeat.GetVulnerabilities(), "Expected to find vulnerabilities for %s:%s", expectedFeat.GetName(), expectedFeat.GetVersion())
						assertIsSubset(t, gotFeat.GetVulnerabilities(), expectedFeat.GetVulnerabilities())
					}
				}
				assert.Truef(t, found, "expected to find feat '%s:%s' in the reply, but got none. Features in the reply: %+v", expectedFeat.GetName(), expectedFeat.GetVersion(), resp.GetInventoryFeatures())
			}
			assert.Equal(t, c.responseContains.GetNotes(), resp.GetNotes())
		})
	}
}

// assertIsSubset asserts that every element of expectedToExist exists in gotVulns
func assertIsSubset(t *testing.T, gotVulns, expectedToExist []*v1.Vulnerability) {
	// Prune last modified time
	for _, v := range gotVulns {
		v.MetadataV2.LastModifiedDateTime = ""
	}
	for _, v := range expectedToExist {
		v.MetadataV2.LastModifiedDateTime = ""
		assert.Contains(t, gotVulns, v, "Expected to find %v among %v", v, gotVulns)
	}
}
