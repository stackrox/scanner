package orchestratorscan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	scannerV1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/archop"
	"github.com/stretchr/testify/assert"
)

type mockRHELv2Datastore struct {
	database.MockDatastore

	layers map[string][]*database.RHELv2Layer

	vulns map[int][]*database.RHELv2Vulnerability
}

func TestOpenShiftVulnVersion(t *testing.T) {
	db := &mockRHELv2Datastore{
		layers: make(map[string][]*database.RHELv2Layer),
		vulns:  make(map[int][]*database.RHELv2Vulnerability),
	}

	testCases := []*struct {
		name            string
		version         string
		fixedInVersions []string
		titles          []string
		expect          set.StringSet
	}{
		{
			name:    "3.11",
			version: "v3.11.420",
			fixedInVersions: []string{
				"0:3.11.219-1.git.0.8845382.el7",
				"0:3.11.420-1.git.0.8845382",
				"0:3.11.421-1.git.0.8888382.el8",
				"",
			},
			titles: []string{
				"xxx yyy zzz",
				"",
				"something else",
				"Fixed in 3.22.1",
			},
			expect: set.StringSet{
				"3.11.421": {},
				"":         {},
			},
		},
		{
			name:    "4.3",
			version: "4.3.9",
			fixedInVersions: []string{
				"0:4.3.31-202007280738.p0.git.0.9884401.el7",
				"0:4.3.0-202001131753.git.0.0aee6a8.el8",
				"0:4.3.9-202003230116.git.0.ebf9a26.el8",
				"",
			},
			titles: []string{
				"xxx yyyzzz",
				"something else",
				"OpenShift Container Platform 4.3.6 package security update",
				"",
			},
			expect: set.StringSet{
				"4.3.31": {},
				"":       {},
			},
		},
		{
			name:    "4.5",
			version: "4.5.1",
			fixedInVersions: []string{
				"0:4.5.0-202102261511.p0.git.0.f0229b9.el7",
				"",
				"0:4.5.0-202104012112.p0.git.0.582d7fc.el8",
				"0:4.5.0-202004012182.p0.git.0.582d7fc",
			},
			titles: []string{
				"OpenShift Container Platform 4.5 package security update (Moderate)",
				"OpenShift Container Platform 4.5.6 package security update",
				"OpenShift Container Platform 4.5.9 package security update",
				"OpenShift Container Platform 4.5.0 package security update",
			},
			expect: set.StringSet{
				"4.5.9": {},
				"":      {},
			},
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			db.FctGetRHELv2Vulnerabilities = func(records []*database.RHELv2Record) (map[int][]*database.RHELv2Vulnerability, error) {
				var vulns []*database.RHELv2Vulnerability
				assert.Equal(t, 1, len(records))
				record := records[0]
				assert.Equal(t, "", record.Pkg.Module)
				cpe := "cpe:/a:redhat:openshift:" + c.name
				assert.Equal(t, cpe, record.CPE)

				if c.name != "3.11" {
					assert.Equal(t, "openshift-hyperkube", record.Pkg.Name)
				} else {
					assert.Equal(t, "atomic-openshift-hyperkube", record.Pkg.Name)
				}
				for i, fixedIn := range c.fixedInVersions {
					vulns = append(vulns,
						&database.RHELv2Vulnerability{
							Model:       database.Model{},
							Name:        fmt.Sprintf("CVE-0000%d", i),
							Title:       c.titles[i],
							Description: "Something real",
							Issued:      time.Time{},
							Updated:     time.Time{},
							Link:        "https://access.redhat.com/security/cve/CVE-123",
							Severity:    "Important",
							CVSSv2:      "4.0/AV:N/AC:H/Au:N/C:P/I:P/A:N",
							CPEs: []string{
								cpe,
							},
							Packages: []*database.RHELv2Package{
								{
									Name:           "package",
									FixedInVersion: fixedIn,
									Arch:           "x86_64",
									ArchOperation:  archop.OpEquals,
								},
							},
						})
				}
				resp := make(map[int][]*database.RHELv2Vulnerability)
				resp[record.Pkg.ID] = vulns
				return resp, nil
			}
			service := NewService(db, nil)
			req := &scannerV1.GetOpenShiftVulnerabilitiesRequest{
				OpenShiftVersion: c.version,
			}
			resp, err := service.GetOpenShiftVulnerabilities(context.Background(), req)
			assert.NoError(t, err)
			vulns := resp.Vulnerabilities
			assert.Equal(t, len(c.expect), len(vulns))
			for _, vuln := range vulns {
				assert.Equal(t, true, c.expect.Contains(vuln.FixedBy))
			}
		})
	}
}
