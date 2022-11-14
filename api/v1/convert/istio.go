package convert

import (
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/istio-cves/types"
	"github.com/stackrox/rox/pkg/stringutils"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/istioutil"
	pkgtypes "github.com/stackrox/scanner/pkg/types"
)

// IstioVulnerabilities converts istio cve schema to vulnerability.
func IstioVulnerabilities(vStr string, istioVulns []types.Vuln) []*v1.Vulnerability {
	res := make([]*v1.Vulnerability, 0, len(istioVulns))
	v, err := version.NewVersion(vStr)
	if err != nil {
		log.Infof("Failed to get version: %s", vStr)
		return nil
	}
	for _, istioVuln := range istioVulns {
		m, err := pkgtypes.ConvertMetadataFromIstio(istioVuln)
		if err != nil {
			log.Errorf("unable to convert metadata for %s: %istioVuln", istioVuln.Name, err)
			continue
		}
		if m.IsNilOrEmpty() {
			log.Warnf("nil or empty metadata for %s", istioVuln.Name)
			continue
		}

		link := stringutils.OrDefault(istioVuln.Link, "https://istio.io/latest/news/security/")
		// Only second returned value is needed for fixed by version in response
		_, fixedBy, err := istioutil.IsAffected(v, istioVuln)
		if err != nil {
			log.Errorf("unable to get fixedBy for %s: %v", istioVuln.Name, err)
			continue
		}

		res = append(res, &v1.Vulnerability{
			Name:        istioVuln.Name,
			Description: istioVuln.Description,
			Link:        link,
			MetadataV2:  Metadata(m),
			FixedBy:     fixedBy,
			Severity:    string(DatabaseSeverityToSeverity(m.GetDatabaseSeverity())),
		})
	}
	return res
}
