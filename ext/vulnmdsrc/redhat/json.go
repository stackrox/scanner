package redhat

import (
	"math"
	"strconv"

	"github.com/facebookincubator/nvdtools/cvss2"
	"github.com/facebookincubator/nvdtools/cvss3"
	"github.com/stackrox/scanner/ext/vulnmdsrc"
)

type redhat []redhatEntry

// See https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/cve#cve_format
// for other fields, if necessary.
type redhatEntry struct {
	CVE                 string `json:"CVE"`
	Severity            string `json:"severity"`
	PublicDate          string `json:"public_date"`
	BugzillaDescription string `json:"bugzilla_description"`
	CVSSv2              string `json:"cvss_score"`
	CVSSv2Vector        string `json:"cvss_scoring_vector"`
	CVSSv3              string `json:"cvss3_score"`
	CVSSv3Vector        string `json:"cvss3_scoring_vector"`
}

func (r *redhatEntry) Summary() string {
	return r.BugzillaDescription
}

func (r *redhatEntry) Metadata() *vulnmdsrc.Metadata {
	metadata := &vulnmdsrc.Metadata{
		PublishedDateTime: r.PublicDate,
	}

	cvss2Score, err := strconv.ParseFloat(r.CVSSv2, 64)
	if err == nil {
		v, err := cvss2.VectorFromString(r.CVSSv2Vector)
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv2 = vulnmdsrc.MetadataCVSSv2{
			Vectors:             r.CVSSv2Vector,
			Score:               cvss2Score,
			ExploitabilityScore: roundTo1Decimal(v.ExploitabilityScore()),
			ImpactScore:         roundTo1Decimal(v.ImpactScore(false)),
		}
	}

	cvss3Score, err := strconv.ParseFloat(r.CVSSv3, 64)
	if err == nil {
		v, err := cvss3.VectorFromString(r.CVSSv3Vector)
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv3 = vulnmdsrc.MetadataCVSSv3{
			Vectors:             r.CVSSv3Vector,
			Score:               cvss3Score,
			ExploitabilityScore: roundUp(v.ExploitabilityScore()),
			ImpactScore:         roundUp(v.ImpactScore()),
		}
	}

	return metadata
}

func (r *redhatEntry) Name() string {
	return r.CVE
}

// Used for CVSSv2
func roundTo1Decimal(x float64) float64 {
	return math.Round(x*10) / 10
}

// Used for CVSSv3
func roundUp(x float64) float64 {
	// round up to one decimal
	return math.Ceil(x*10) / 10
}
