//go:build e2e
// +build e2e

package e2etests

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stackrox/rox/pkg/set"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stretchr/testify/assert"
)

var (
	patchRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.([0-9]+)$`)
)

func TestGRPCGetOpenShiftVulnerabilities(t *testing.T) {
	conn := connectToScanner(t)
	client := v1.NewOrchestratorScanServiceClient(conn)

	// Map from address families to their current state.
	testCases := []*struct {
		addressFamily string
		maxPatch      int
		step          int
		knownFixed    int
	}{
		{
			addressFamily: "3.11",
			maxPatch:      439,
			step:          1,
			knownFixed:    19,
		},
		{
			addressFamily: "4.5",
			maxPatch:      40,
			step:          1,
			knownFixed:    5,
		},
		{
			addressFamily: "4.7",
			maxPatch:      12,
			step:          1,
			knownFixed:    3,
		},
	}

	for _, c := range testCases {
		t.Run(fmt.Sprintf("case-%s", c.addressFamily), func(t *testing.T) {
			req := &v1.GetOpenShiftVulnerabilitiesRequest{
				OpenShiftVersion: c.addressFamily + ".0",
			}
			resp, err := client.GetOpenShiftVulnerabilities(context.Background(), req)
			assert.NoError(t, err)
			initialSize := len(resp.Vulnerabilities)
			vulnNameMap := make(map[string]*v1.Vulnerability)
			for _, vuln := range resp.GetVulnerabilities() {
				if strings.HasPrefix(vuln.Name, "RHBA-") || strings.HasPrefix(vuln.Name, "RHSA-") {
					assert.True(t, strings.HasPrefix(vuln.FixedBy, c.addressFamily))
				} else if strings.HasPrefix(vuln.Name, "CVE-") {
					assert.Empty(t, vuln.FixedBy)
				}
				assert.True(t, vuln.MetadataV2.CvssV2 != nil || vuln.MetadataV2.CvssV3 != nil)
				vulnNameMap[vuln.Name] = vuln
			}
			assert.Equal(t, initialSize, len(vulnNameMap))

			lastPatch := 0
			for patch := 1; patch <= c.maxPatch; patch += c.step {
				req := &v1.GetOpenShiftVulnerabilitiesRequest{
					OpenShiftVersion: fmt.Sprintf("%s.%d", c.addressFamily, patch),
				}
				resp, err = client.GetOpenShiftVulnerabilities(context.Background(), req)
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, len(vulnNameMap), len(resp.Vulnerabilities))
				var currNames set.StringSet
				// Verify a fixed vuln not showing up in later release.
				for _, vuln := range resp.GetVulnerabilities() {
					assert.True(t, currNames.Add(vuln.Name))
					_, ok := vulnNameMap[vuln.Name]
					assert.True(t, ok)
				}

				// Verify the fixedBy version is within this step.
				for name, vuln := range vulnNameMap {
					if !currNames.Contains(name) {
						assert.NotEmpty(t, vuln.FixedBy)
						assert.GreaterOrEqual(t, patch, getPatch(t, vuln.FixedBy))
						assert.Greater(t, getPatch(t, vuln.FixedBy), lastPatch)
						delete(vulnNameMap, vuln.Name)
					}
				}

				lastPatch = patch
			}

			// Check for regression. All vulns known to be fixed should not be unfixed.
			assert.GreaterOrEqual(t, initialSize, len(vulnNameMap)+c.knownFixed)
			t.Logf("Fixed %d vulns from %s.0 to %s.%d", initialSize-len(vulnNameMap), c.addressFamily, c.addressFamily, c.maxPatch)
		})
	}
}

func getPatch(t *testing.T, ver string) int {
	matched := patchRegex.FindStringSubmatch(ver)
	assert.Equal(t, 2, len(matched))
	patch, err := strconv.Atoi(matched[1])
	assert.NoError(t, err)
	return patch
}
