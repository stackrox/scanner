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

type redhatEntry struct {
	Entry
}

type Entry interface {
	GetCVE() string
	GetPublicDate() string
	GetDescription() string
	GetCVSSv2() *float64
	GetCVSSv2Vector() string
	GetCVSSv3() *float64
	GetCVSSv3Vector() string
}

// See https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/cve#cve_format
// for other fields, if necessary.

type stringEntry struct {
	CVE                 string `json:"CVE"`
	PublicDate          string `json:"public_date"`
	BugzillaDescription string `json:"bugzilla_description"`
	CVSSv2              string `json:"cvss_score"`
	CVSSv2Vector        string `json:"cvss_scoring_vector"`
	CVSSv3              string `json:"cvss3_score"`
	CVSSv3Vector        string `json:"cvss3_scoring_vector"`
}

func (e *stringEntry) GetCVE() string {
	return e.CVE
}

func (e *stringEntry) GetPublicDate() string {
	return e.PublicDate
}

func (e *stringEntry) GetDescription() string {
	return e.BugzillaDescription
}

func (e *stringEntry) GetCVSSv2() *float64 {
	cvss2Score, err := strconv.ParseFloat(e.CVSSv2, 64)
	if err != nil {
		return nil
	}

	return &cvss2Score
}

func (e *stringEntry) GetCVSSv2Vector() string {
	return e.CVSSv2Vector
}

func (e *stringEntry) GetCVSSv3() *float64 {
	cvss3Score, err := strconv.ParseFloat(e.CVSSv3, 64)
	if err != nil {
		return nil
	}

	return &cvss3Score
}

func (e *stringEntry) GetCVSSv3Vector() string {
	return e.CVSSv3Vector
}

type floatEntry struct {
	CVE                 string   `json:"CVE"`
	Severity            string   `json:"severity"`
	PublicDate          string   `json:"public_date"`
	BugzillaDescription string   `json:"bugzilla_description"`
	CVSSv2              *float64 `json:"cvss_score"`
	CVSSv2Vector        string   `json:"cvss_scoring_vector"`
	CVSSv3              *float64 `json:"cvss3_score"`
	CVSSv3Vector        string   `json:"cvss3_scoring_vector"`
}

func (e *floatEntry) GetCVE() string {
	return e.CVE
}

func (e *floatEntry) GetPublicDate() string {
	return e.PublicDate
}

func (e *floatEntry) GetDescription() string {
	return e.BugzillaDescription
}

func (e *floatEntry) GetCVSSv2() *float64 {
	return e.CVSSv2
}

func (e *floatEntry) GetCVSSv2Vector() string {
	return e.CVSSv2Vector
}

func (e *floatEntry) GetCVSSv3() *float64 {
	return e.CVSSv3
}

func (e *floatEntry) GetCVSSv3Vector() string {
	return e.CVSSv3Vector
}

func (r *redhatEntry) Summary() string {
	return r.GetDescription()
}

func (r *redhatEntry) Metadata() *vulnmdsrc.Metadata {
	metadata := &vulnmdsrc.Metadata{
		PublishedDateTime: r.GetPublicDate(),
	}

	cvss2Score := r.GetCVSSv2()
	if cvss2Score != nil {
		v, err := cvss2.VectorFromString(r.GetCVSSv2Vector())
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv2 = vulnmdsrc.MetadataCVSSv2{
			Vectors:             r.GetCVSSv2Vector(),
			Score:               *cvss2Score,
			ExploitabilityScore: roundTo1Decimal(v.ExploitabilityScore()),
			ImpactScore:         roundTo1Decimal(v.ImpactScore(false)),
		}
	}

	cvss3Score := r.GetCVSSv3()
	if cvss3Score != nil {
		v, err := cvss3.VectorFromString(r.GetCVSSv3Vector())
		if err != nil || v.Validate() != nil {
			return nil
		}
		metadata.CVSSv3 = vulnmdsrc.MetadataCVSSv3{
			Vectors:             r.GetCVSSv3Vector(),
			Score:               *cvss3Score,
			ExploitabilityScore: roundUp(v.ExploitabilityScore()),
			ImpactScore:         roundUp(v.ImpactScore()),
		}
	}

	return metadata
}

func (r *redhatEntry) Name() string {
	return r.GetCVE()
}

func (r *redhatEntry) UnmarshalJSON(data []byte) error {
	errorList := errorhelpers.NewErrorList("parsing red hat cve data")
	var err error

	var strEntry stringEntry
	if err = json.Unmarshal(data, &strEntry); err == nil {
		r.Entry = &strEntry
		return nil
	}
	errorList.AddError(err)

	var fEntry floatEntry
	if err = json.Unmarshal(data, &fEntry); err == nil {
		r.Entry = &fEntry
		return nil
	}
	errorList.AddError(err)

	return errorList.ToError()
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
