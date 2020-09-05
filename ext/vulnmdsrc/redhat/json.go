package redhat

import (
	"encoding/json"
	"math"
	"strconv"

	"github.com/facebookincubator/nvdtools/cvss2"
	"github.com/facebookincubator/nvdtools/cvss3"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/scanner/ext/vulnmdsrc"
)

type redhat []redhatEntry

// See https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/cve#cve_format
// for other fields, if necessary.
type redhatEntry struct {
	CVE                 string    `json:"CVE"`
	PublicDate          string    `json:"public_date"`
	BugzillaDescription string    `json:"bugzilla_description"`
	CVSSv2              cvssScore `json:"cvss_score"`
	CVSSv2Vector        string    `json:"cvss_scoring_vector"`
	CVSSv3              cvssScore `json:"cvss3_score"`
	CVSSv3Vector        string    `json:"cvss3_scoring_vector"`
}

type cvssScore struct {
	stringScore string
	floatScore  *float64
}

func (c *cvssScore) Score() *float64 {
	if c.floatScore != nil {
		return c.floatScore
	}

	score, err := strconv.ParseFloat(c.stringScore, 64)
	if err != nil {
		return nil
	}

	return &score
}

func (c *cvssScore) UnmarshalJSON(data []byte) error {
	errorList := errorhelpers.NewErrorList("parsing red hat cvss score")
	var err error

	var str string
	if err = json.Unmarshal(data, &str); err == nil {
		c.stringScore = str
		return nil
	}
	errorList.AddError(err)

	var flt float64
	if err = json.Unmarshal(data, &flt); err == nil {
		c.floatScore = &flt
		return nil
	}
	errorList.AddError(err)

	return errorList.ToError()
}

func (r *redhatEntry) Summary() string {
	return r.BugzillaDescription
}

func (r *redhatEntry) Metadata() *vulnmdsrc.Metadata {
	metadata := &vulnmdsrc.Metadata{
		PublishedDateTime: r.PublicDate,
	}

	if r.CVSSv2Vector != "" {
		v, err := cvss2.VectorFromString(r.CVSSv2Vector)
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv2 = vulnmdsrc.MetadataCVSSv2{
			Vectors:             r.CVSSv2Vector,
			Score:               *r.CVSSv2.Score(),
			ExploitabilityScore: roundTo1Decimal(v.ExploitabilityScore()),
			ImpactScore:         roundTo1Decimal(v.ImpactScore(false)),
		}
	}

	if r.CVSSv3Vector != "" {
		v, err := cvss3.VectorFromString(r.CVSSv3Vector)
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv3 = vulnmdsrc.MetadataCVSSv3{
			Vectors:             r.CVSSv3Vector,
			Score:               *r.CVSSv3.Score(),
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
