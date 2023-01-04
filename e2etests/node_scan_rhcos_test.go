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

func buildRequest(notes []v1.Note) *v1.GetNodeVulnerabilitiesRequest {
	// From: https://www.redhat.com/security/data/metrics/repository-to-cpe.json
	// "rhel-8-for-x86_64-appstream-rpms": {"cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream"]},
	// "rhel-8-for-x86_64-baseos-rpms": {"cpes": ["cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:rhel:8.3::baseos"]}
	cpes := []string{
		"cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:rhel:8.3::appstream",
		"cpe:/a:redhat:enterprise_linux:8::baseos", "cpe:/a:redhat:rhel:8.3::baseos",
	}
	return &v1.GetNodeVulnerabilitiesRequest{
		OsImage:          "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",
		KernelVersion:    "0.0.1", // dummy value - out of scope for this test
		KubeletVersion:   "0.0.1", // dummy value - out of scope for this test
		KubeproxyVersion: "0.0.1", // dummy value - out of scope for this test
		Runtime: &v1.GetNodeVulnerabilitiesRequest_ContainerRuntime{
			Name:    "docker",
			Version: "0.0.1", // dummy value - out of scope for this test
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
		expectedResponse *v1.GetNodeVulnerabilitiesResponse
		assertVulnsLen   func(t *testing.T, expected, got int, msgAndArgs ...interface{}) bool
	}{
		{
			name:    "Selected vulnerabilities should be returned by the certified scan",
			request: buildRequest([]v1.Note{}),
			expectedResponse: &v1.GetNodeVulnerabilitiesResponse{
				// We conduct a spot-checking here - more vulns can be returned from scanner for libksba and tar,
				// but we care only about the selected one as it is sufficient for this test case.
				// (We do not test that the set of vulns is complete, we test that the API returns any vulns if expected).
				// We use 'equals' assertion if 0 vulns are expected.
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
						Name:    "grep",
						Version: "3.1-6.el8.x86_64",
						// Warning: if this test fails, it may mean that new vulnerabilities have been found for grep:3.1-6
						// To fix that, one would need to find another package/version that has 0 vulnerabilities
						// or mock the scanning behavior of scanner to always return 0 vulnerabilities for the pkg used in this case.
						Vulnerabilities: []*v1.Vulnerability{},
					},
				},
				NodeNotes: nil,
			},
		},
		{
			name:    "Uncertified scan is unsupported for RHCOS and returns no features",
			request: buildRequest([]v1.Note{v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE}),
			expectedResponse: &v1.GetNodeVulnerabilitiesResponse{
				Features:  []*v1.Feature{},
				NodeNotes: nil,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c := c
			gotResponse, err := client.GetNodeVulnerabilities(context.Background(), c.request)
			require.NoError(t, err)
			assert.Len(t, gotResponse.GetFeatures(), len(c.expectedResponse.GetFeatures()), "Unexpected number of features") // unusual got-expected order of Len
			assert.Len(t, gotResponse.GetNodeNotes(), len(c.expectedResponse.GetNodeNotes()))

			for _, expectedFeat := range c.expectedResponse.GetFeatures() {
				foundFeat := findFeat(expectedFeat.GetName(), expectedFeat.GetVersion(), gotResponse.GetFeatures())
				assert.NotNil(t, foundFeat, "Expected to find feature '%s:%s'", expectedFeat.GetName(), expectedFeat.GetVersion())
				if foundFeat == nil {
					continue
				}
				// when 0 vulns are expected, then use stronger assertion, because empty set is a subset of any set
				if len(expectedFeat.GetVulnerabilities()) == 0 {
					assert.Len(t, foundFeat.GetVulnerabilities(), 0, "Expected to find 0 vulnerabilities for feature '%s:%s'", expectedFeat.GetName(), expectedFeat.GetVersion())
				} else {
					assertIsSubset(t, expectedFeat.GetVulnerabilities(), foundFeat.GetVulnerabilities())
				}
			}
		})
	}
}

func findFeat(name, version string, set []*v1.Feature) *v1.Feature {
	for _, gotFeat := range set {
		if gotFeat.GetName() == name && gotFeat.GetVersion() == version {
			return gotFeat
		}
	}
	return nil
}

// assertIsSubset asserts that every element of 'subset' exists in 'set'
func assertIsSubset(t *testing.T, subset, set []*v1.Vulnerability) {
	assert.GreaterOrEqual(t, len(set), len(subset), "Expected to find at least %d vulnerabilities", len(subset))
	// Prune last modified time
	for _, v := range set {
		v.MetadataV2.LastModifiedDateTime = ""
	}
	for _, v := range subset {
		assert.Contains(t, set, v)
	}
}
