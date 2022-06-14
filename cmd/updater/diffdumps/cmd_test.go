package diffdumps

import (
	"testing"

	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stretchr/testify/assert"
)

func getVuln(namespace string, fixInVersions ...string) database.Vulnerability {
	fixedIn := make([]database.FeatureVersion, 0, len(fixInVersions))
	for _, fixInVersion := range fixInVersions {
		fixedIn = append(fixedIn, database.FeatureVersion{Feature: database.Feature{Name: uuid.NewV4().String()}, Version: fixInVersion})
	}
	return database.Vulnerability{
		Namespace: database.Namespace{Name: namespace},
		Name:      uuid.NewV4().String(),
		FixedIn:   fixedIn,
	}
}

func TestFilterFixableCentOSVulns(t *testing.T) {
	nonCentOSVulnWithNonFixable := getVuln("debian:8", versionfmt.MaxVersion)
	nonCentOSVulnWithFixable := getVuln("debian:8", "1.2.3")
	nonCentOSVulnWithFixableAndNonFixable := getVuln("debian:8", "1.2.3", versionfmt.MaxVersion)
	centOSVulnWithNonFixable := getVuln("centos:8", versionfmt.MaxVersion)
	centOSVulnWithFixable := getVuln("centos:8", "1.2.3")
	centOSVulnWithFixableAndNonFixable := getVuln("centos:8", "1.2.3", versionfmt.MaxVersion)
	out := filterFixableCentOSVulns([]database.Vulnerability{
		nonCentOSVulnWithNonFixable, nonCentOSVulnWithFixable, nonCentOSVulnWithFixableAndNonFixable,
		centOSVulnWithNonFixable, centOSVulnWithFixable, centOSVulnWithFixableAndNonFixable,
	})
	// Remove the non-fixable feature.
	centOSVulnWithFixableAndNonFixable.FixedIn = centOSVulnWithFixableAndNonFixable.FixedIn[:1]
	assert.Equal(t, []database.Vulnerability{
		nonCentOSVulnWithNonFixable, nonCentOSVulnWithFixable, nonCentOSVulnWithFixableAndNonFixable,
		centOSVulnWithFixable, centOSVulnWithFixableAndNonFixable,
	}, out)
}

func TestUpdateUbuntuLink(t *testing.T) {
	vuln := database.Vulnerability{
		Name: "CVE-2021-1234",
		Namespace: database.Namespace{
			Name:          "ubuntu:21.10",
			VersionFormat: "dpkg",
		},
		Link: "https://ubuntu.com/security/CVE-2021-1234",
	}

	cfg := config{UseLegacyUbuntuCVEURLPrefix: false}
	updateUbuntuLink(cfg, &vuln)
	assert.Equal(t, "https://ubuntu.com/security/CVE-2021-1234", vuln.Link)

	cfg.UseLegacyUbuntuCVEURLPrefix = true
	updateUbuntuLink(cfg, &vuln)
	assert.Equal(t, "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2021-1234", vuln.Link)
}

func TestUpdateAlpineLink(t *testing.T) {
	vuln := database.Vulnerability{
		Name: "CVE-2021-1234",
		Namespace: database.Namespace{
			Name:          "alpine:v3.13",
			VersionFormat: "apk",
		},
		Link: "https://www.cve.org/CVERecord?id=CVE-2021-1234",
	}

	cfg := config{UseLegacyAlpineCVEURLPrefix: false}
	updateAlpineLink(cfg, &vuln)
	assert.Equal(t, "https://www.cve.org/CVERecord?id=CVE-2021-1234", vuln.Link)

	cfg.UseLegacyAlpineCVEURLPrefix = true
	updateAlpineLink(cfg, &vuln)
	assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1234", vuln.Link)
}
