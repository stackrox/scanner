package node

import (
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	knownPkgs = set.NewFrozenStringSet("cryptiles", "qs", "brace_expansion")
)

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	if knownPkgs.Contains(result.CPE.Product) {
		return true
	}
	for _, a := range result.CVE.Config() {
		if a.TargetSW == `node\.js` {
			return true
		}
	}
	log.Debugf("NodeJS failed validation: %s %s", result.CPE.Product, result.CVE.ID())
	return false
}

func init() {
	validation.Register(component.NPMSourceType, &validator{})
}
