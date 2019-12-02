package python

import (
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	knownPkgs = set.NewFrozenStringSet("ansible", "jinja2")
)

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	if result.CPE.Vendor != "" {
		return true
	}
	if knownPkgs.Contains(result.CPE.Product) {
		return true
	}
	if strings.Contains(result.CPE.Vendor, "py") {
		return true
	}
	if strings.Contains(result.CPE.Product, "py") {
		return true
	}
	if strings.Contains(strings.ToLower(result.Vuln.Description), "py") {
		return true
	}
	log.Debugf("Python (%s %s): %s failed validation: %v", result.CPE.Vendor, result.CPE.Product, result.CVE.ID(), result.Vuln.Description)
	return false
}

func init() {
	validation.Register(component.PythonSourceType, &validator{})
}
