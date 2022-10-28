package convert

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/istio-cves/types"
	"github.com/stackrox/rox/pkg/stringutils"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/istioUtil"
	pkgtypes "github.com/stackrox/scanner/pkg/types"
)

// IstioVulnerabilities converts istio cve schema to vulnerability.
func IstioVulnerabilities(version string, istioVulns []types.Vuln) []*v1.Vulnerability {
	res := make([]*v1.Vulnerability, 0, len(istioVulns))
	for _, v := range istioVulns {
		m, err := pkgtypes.ConvertMetadataFromIstio(v)
		if err != nil {
			log.Errorf("unable to convert metadata for %s: %v", v.Name, err)
			continue
		}
		if m.IsNilOrEmpty() {
			log.Warnf("nil or empty metadata for %s", v.Name)
			continue
		}

		link := stringutils.OrDefault(v.Link, "https://istio.io/latest/news/security/")
		_, fixedBy, err := istioUtil.IstioIsAffected(version, v)
		if err != nil {
			log.Errorf("unable to get fixedBy for %s: %v", v.Name, err)
			continue
		}

		res = append(res, &v1.Vulnerability{
			Name:        v.Name,
			Description: v.Description,
			Link:        link,
			MetadataV2:  Metadata(m),
			FixedBy:     fixedBy,
			Severity:    string(DatabaseSeverityToSeverity(m.GetDatabaseSeverity())),
		})
	}
	return res
}
