//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"testing"

	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vulnLibksba is an example of a fixable vulnerability (potentially one of many others that exist for this version)
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

// vulnTar is an example of a non-fixable vulnerability (potentially one of many others that exist for this version)
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

func buildRequestCase(notes []v1.Note) *v1.GetNodeVulnerabilitiesRequest {
	// From: https://www.redhat.com/security/data/metrics/repository-to-cpe.json
	// "rhel-8-for-x86_64-appstream-rpms": {"cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream"]},
	// "rhel-8-for-x86_64-baseos-rpms": {"cpes": ["cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:rhel:8.3::baseos"]}
	cpes := []string{
		"cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream",
		"cpe:/a:redhat:enterprise_linux:8::baseos", "cpe:/a:redhat:rhel:8.3::baseos",
	}
	return &v1.GetNodeVulnerabilitiesRequest{
		OsImage:          "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",
		KernelVersion:    "0.0.1",
		KubeletVersion:   "0.0.1",
		KubeproxyVersion: "0.0.1",
		Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
			Name:    "docker",
			Version: "0.0.1",
		},
		Notes: notes,
		Components: &v1.Components{
			Namespace: "rhcos:4.11",
			RhelComponents: []*v1.RHELComponent{
				{
					Id:        int64(1),
					Name:      "libksba",
					Namespace: "rhel:8",
					Version:   "1.3.5-7.el8",
					Arch:      "x86_64",
					Module:    "", // must be empty, otherwise scanner does not return any vulns
					Cpes:      cpes,
					AddedBy:   "",
				},
				{
					Id:        int64(2),
					Name:      "tar",
					Namespace: "rhel:8",
					Version:   "1.27.1.el8",
					Arch:      "x86_64",
					Module:    "",
					Cpes:      cpes,
					AddedBy:   "",
				},
				{
					Id:        int64(3),
					Name:      "grep",
					Namespace: "rhel:8",
					Version:   "3.1-6.el8",
					Arch:      "x86_64",
					Module:    "",
					Cpes:      cpes,
					AddedBy:   "",
				},
			},
			LanguageComponents: nil,
		},
	}
}

func TestGRPCGetRHCOSNodeVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewNodeScanServiceClient(conn)

	cases := []struct {
		name             string
		request          *v1.GetNodeVulnerabilitiesRequest
		responseContains *v1.GetNodeVulnerabilitiesResponse
	}{
		{
			name:    "Selected vulnerabilities should be returned by the certified scan",
			request: buildRequestCase([]v1.Note{}),
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				// We conduct a spot-checking here - more vulns can be returned from scanner for libksba and tar,
				// but we care only about the selected one as it is sufficient for this test case.
				// (We do not test that the set of vulns is complete, we test that the API returns any vulns if expected)
				Features: []*v1.Feature{
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
					{
						Name:            "grep",
						Version:         "3.1-6.el8.x86_64",
						Vulnerabilities: []*v1.Vulnerability{},
					},
				},
				NodeNotes: nil,
			},
		},
		{
			name:    "Uncertified scan is unsupported for RHCOS and returns no features",
			request: buildRequestCase([]v1.Note{v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE}),
			responseContains: &v1.GetNodeVulnerabilitiesResponse{
				Features:  []*v1.Feature{},
				NodeNotes: nil,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c := c
			resp, err := client.GetNodeVulnerabilities(context.Background(), c.request)
			require.NoError(t, err)
			assert.Len(t, resp.GetFeatures(), len(c.responseContains.GetFeatures()))
			for _, expectedFeat := range c.responseContains.GetFeatures() {
				var feat *v1.Feature
				for _, gotFeat := range resp.GetFeatures() {
					if expectedFeat.GetName() == gotFeat.GetName() && expectedFeat.GetVersion() == gotFeat.GetVersion() {
						feat = gotFeat
					}
				}
				assert.NotNil(t, feat, "expected to find feat '%s:%s' in the reply, but got none. Features in the reply: %+v", expectedFeat.GetName(), expectedFeat.GetVersion(), resp.GetFeatures())
				assertIsSubset(t, feat.GetVulnerabilities(), expectedFeat.GetVulnerabilities())
			}
			assert.Equal(t, c.responseContains.GetNodeNotes(), resp.GetNodeNotes())
		})
	}
}

// assertIsSubset asserts that every element of expectedToExist exists in gotVulns
func assertIsSubset(t *testing.T, gotVulns, expectedToExist []*v1.Vulnerability) {
	assert.GreaterOrEqual(t, len(gotVulns), len(expectedToExist), "Expected %d vulnerabilities to be a subset of a set that has %d elements", len(gotVulns), len(expectedToExist))
	// Prune last modified time
	for _, v := range gotVulns {
		v.MetadataV2.LastModifiedDateTime = ""
	}
	for _, v := range expectedToExist {
		assert.Contains(t, gotVulns, v, "Expected to find %v among %v", v, gotVulns)
	}
}
