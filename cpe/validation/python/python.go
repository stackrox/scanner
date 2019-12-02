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
	knownPkgs = set.NewFrozenStringSet("ansible", "jinja2", "supervisor", "html5lib", "sqlalchemy")

	keywords = []string{
		"beaker", "flask", "pallets", "py",
	}
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
	desc := strings.ToLower(result.Vuln.Description)
	for _, k := range keywords {
		if strings.Contains(desc, k) {
			return true
		}
	}
	log.Debugf("Python (%s %s): %s failed validation: %v", result.CPE.Vendor, result.CPE.Product, result.CVE.ID(), result.Vuln.Description)
	return false
}

func init() {
	validation.Register(component.PythonSourceType, &validator{})
}
