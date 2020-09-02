package redhat

import "github.com/stackrox/scanner/ext/vulnmdsrc"

type redhat struct {
	Entries []redhatEntry
}

// See https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/cve#cve_format
// for other fields, if necessary.
type redhatEntry struct {
	CVE                 string   `json:"CVE"`
	Severity            string   `json:"severity"`
	PublicDate          string   `json:"public_date"`
	BugzillaDescription string   `json:"bugzilla_description"`
	CVSSv2              string   `json:"cvss_score"`
	CVSSv2Vector        string   `json:"cvss_scoring_vector"`
	CVSSv3              string   `json:"cvss3_score"`
	CVSSv3Vector        string   `json:"cvss3_scoring_vector"`
}

func (r *redhatEntry) Summary() string {
	return ""
}

func (r *redhatEntry) Metadata() *vulnmdsrc.Metadata {
	metadata := &vulnmdsrc.Metadata{
		PublishedDateTime:    r.PublicDate,
		CVSSv2: vulnmdsrc.MetadataCVSSv2{
			Vectors:             n.Impact.BaseMetricV2.CVSSv2.String(),
			Score:               n.Impact.BaseMetricV2.CVSSv2.Score,
			ExploitabilityScore: n.Impact.BaseMetricV2.ExploitabilityScore,
			ImpactScore:         n.Impact.BaseMetricV2.ImpactScore,
		},
		CVSSv3: vulnmdsrc.MetadataCVSSv3{
			Vectors:             n.Impact.BaseMetricV3.CVSSv3.String(),
			Score:               n.Impact.BaseMetricV3.CVSSv3.Score,
			ExploitabilityScore: n.Impact.BaseMetricV3.ExploitabilityScore,
			ImpactScore:         n.Impact.BaseMetricV3.ImpactScore,
		},
	}

	return metadata
}

func (r *redhatEntry) Name() string {
	return r.CVE
}
