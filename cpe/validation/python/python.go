package python

import (
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	if result.CPE.Vendor != "" {
		return true
	}
	if strings.Contains(result.CPE.Vendor, "python") {
		return true
	}
	if strings.Contains(result.CPE.Product, "python") {
		return true
	}
	log.Debugf("Python %s: %s failed validation", result.CPE.Product, result.CVE.ID())
	return false
}

func init() {
	validation.Register(component.PythonSourceType, &validator{})
}
