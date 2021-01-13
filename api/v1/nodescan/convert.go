package nodescan

import (
	"regexp"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/api/v1/convert"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/types"
)

var (
	semverPattern = regexp.MustCompile(`(?:v)?([0-9]+.[0-9]+.[0-9]+)(?:[-+]?.*)`)
)

// truncateVersion converts the given version into a semantic version x.y.z.
// Returns empty string ""
func truncateVersion(v string) (string, error) {
	vs := semverPattern.FindStringSubmatch(v)
	if len(vs) == 2 {
		return vs[1], nil
	}
	return "", errors.Errorf("unsupported version: %s", v)
}

func convertK8sVulnerabilities(version string, k8sVulns []*validation.CVESchema) ([]*v1.Vulnerability, error) {
	vulns := make([]*v1.Vulnerability, 0, len(k8sVulns))
	for _, v := range k8sVulns {
		m, err := types.ConvertMetadataFromK8s(v)
		if err != nil {
			log.Errorf("Unable to convert metadata for %s: %v", v.CVE, err)
			continue
		}

		link := stringutils.OrDefault(v.IssueURL, v.URL)
		fixedBy, err := getFixedBy(version, v)
		if err != nil {
			log.Errorf("Unable to get FixedBy for %s: %v", v.CVE, err)
			continue
		}
		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.CVE,
			Description: v.Description,
			Link:        link,
			MetadataV2:  convert.Metadata(m),
			FixedBy:     fixedBy,
		})
	}
	return vulns, nil
}

func getFixedBy(vStr string, vuln *validation.CVESchema) (string, error) {
	v, err := version.NewVersion(vStr)
	if err != nil {
		return "", err
	}

	for _, affected := range vuln.Affected {
		constraint, err := version.NewConstraint(affected.Range)
		if err != nil {
			return "", err
		}
		if constraint.Check(v) {
			return affected.FixedBy, nil
		}
	}

	return "", nil
}
