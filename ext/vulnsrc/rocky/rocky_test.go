// Package rocky implements a vulnerability source updater using
// ALAS (Amazon Linux Security Advisories).

package rocky

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestRockyParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename)) + "/testdata/fetcher_rocky_test.json")

	response, err := buildResponse(testFile, "")
	if assert.Nil(t, err) && assert.Len(t, response.Vulnerabilities, 1) {
		for _, vulnerability := range response.Vulnerabilities {
			if vulnerability.Name == "RLSA-2022:2199" {
				assert.Equal(t, "https://errata.rockylinux.org/RLSA-2022:2199", vulnerability.Link)
				assert.Equal(t, database.HighSeverity, vulnerability.Severity)
				assert.Equal(t, "This vulnerability is not very dangerous.", vulnerability.Description)

				expectedFeatureVersions := []database.FeatureVersion{
					{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "rocky:8",
								VersionFormat: rpm.ParserName,
							},
							Name: "aspnetcore-runtime-5.0",
						},
						Version: "5.0.17-1.el8_6",
					},
					{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "rocky:8",
								VersionFormat: rpm.ParserName,
							},
							Name: "aspnetcore-runtime-3.1",
						},
						Version: "3.1.25-1.el8_6",
					},
				}

				for _, expectedFeatureVersion := range expectedFeatureVersions {
					assert.Contains(t, vulnerability.FixedIn, expectedFeatureVersion)
				}
			}
		}
	}
}
