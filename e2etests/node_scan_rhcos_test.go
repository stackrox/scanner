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
					Cpes:      []string{},
					AddedBy:   "",
				},
				{
					Id:        int64(2),
					Name:      "tar",
					Namespace: "rhel:8",
					Version:   "1.27.1.el8",
					Arch:      "x86_64",
					Module:    "",
					Cpes:      []string{},
					AddedBy:   "",
				},
				{
					Id:        int64(3),
					Name:      "tzdata",
					Namespace: "rhel:8",
					Version:   "2022g.el8",
					Arch:      "noarch",
					Module:    "",
					Cpes:      []string{},
					AddedBy:   "",
				},
			},
			LanguageComponents: nil,
			RhelContentSets:    []string{"rhel-8-for-x86_64-appstream-rpms", "rhel-8-for-x86_64-baseos-rpms"},
		},
	}
}

func TestGRPCGetRHCOSNodeVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewNodeScanServiceClient(conn)

	type expectedFeatures struct {
		Name                     string
		Version                  string
		ExpectedVulnerabilities  []*v1.Vulnerability
		VulnerabilitiesAssertion func(t2 *testing.T, name, version string, got, expected []*v1.Vulnerability)
	}

	cases := map[string]struct {
		request          *v1.GetNodeVulnerabilitiesRequest
		expectedFeatures []expectedFeatures
		expectedNotes    []*v1.NodeNote
	}{
		"Selected vulnerabilities should be returned by the certified scan": {
			request: buildRequest([]v1.Note{}),
			expectedFeatures: []expectedFeatures{
				{
					Name:                     "libksba",
					Version:                  "1.3.5-7.el8.x86_64",
					ExpectedVulnerabilities:  []*v1.Vulnerability{vulnLibksba},
					VulnerabilitiesAssertion: assertExists,
				},
				{
					Name:                     "tar",
					Version:                  "1.27.1.el8.x86_64",
					ExpectedVulnerabilities:  []*v1.Vulnerability{vulnTar},
					VulnerabilitiesAssertion: assertExists,
				},
				{
					Name:    "tzdata",
					Version: "2022g.el8.noarch",
					// Warning: if this test fails, then probably vulnerabilities have been found for tzdata:2022g
					// To fix that, one would need to find another package/version that has 0 vulnerabilities
					// or mock the scanning behavior of scanner to always return 0 vulnerabilities for the pkg used in this case.
					ExpectedVulnerabilities:  []*v1.Vulnerability{},
					VulnerabilitiesAssertion: assertEquals,
				},
			},
		},
		"Uncertified scan is unsupported for RHCOS and returns no features": {
			request:          buildRequest([]v1.Note{v1.Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE}),
			expectedFeatures: []expectedFeatures{},
			expectedNotes:    nil,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c := c
			gotResponse, err := client.GetNodeVulnerabilities(context.Background(), c.request)
			require.NoError(t, err)
			assert.Len(t, gotResponse.GetFeatures(), len(c.expectedFeatures), "Unexpected number of features") // unusual got-expected order of Len
			assert.Len(t, gotResponse.GetNodeNotes(), len(c.expectedNotes))

			for _, expectedFeat := range c.expectedFeatures {
				foundFeat := findFeat(expectedFeat.Name, expectedFeat.Version, gotResponse.GetFeatures())
				assert.NotNil(t, foundFeat, "Expected to find feature '%s:%s'", expectedFeat.Name, expectedFeat.Version)
				if foundFeat == nil {
					continue
				}
				expectedFeat.VulnerabilitiesAssertion(t, expectedFeat.Name, expectedFeat.Version, expectedFeat.ExpectedVulnerabilities, foundFeat.GetVulnerabilities())
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

// assertEquals asserts that sets 'expected' and 'got' are identical
func assertEquals(t *testing.T, name, version string, expected, got []*v1.Vulnerability) {
	assert.Len(t, got, len(expected), "Expected to find %d vulnerabilities for feature '%s:%s'", len(expected), name, version)
	assertExists(t, name, version, expected, got)
}

// assertExists asserts that all 'needles' exist in 'haystack'
func assertExists(t *testing.T, name, version string, needles, haystack []*v1.Vulnerability) {
	assert.GreaterOrEqual(t, len(haystack), len(needles), "Expected to find at least %d vulnerabilities for feature '%s:%s'", len(needles), name, version)
	// Prune last modified time
	for _, v := range haystack {
		v.MetadataV2.LastModifiedDateTime = ""
	}
	for _, v := range needles {
		assert.Contains(t, haystack, v)
	}
}
