package ruby

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	knownRubyPkgs = set.NewFrozenStringSet("webrick", "sprockets", "sinatra", "foreman", "devise")

	knownKeywords = []string{
		"ruby",
		"gem",
		"rails",
	}

	keywordRegexes = func() []*regexp.Regexp {
		regexps := make([]*regexp.Regexp, 0, len(knownKeywords))
		for _, k := range knownKeywords {
			regexps = append(regexps, regexp.MustCompile(fmt.Sprintf("(?i)%s", k)))
		}
		return regexps
	}()
)

func init() {
	validation.Register(component.GemSourceType, &validator{})
}

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	if knownRubyPkgs.Contains(result.CPE.Product) {
		return true
	}
	// Check if the vuln matches Ruby in the targetSW
	for _, a := range result.CVE.Config() {
		for _, k := range knownKeywords {
			if anyContains(k, a.Vendor, a.Product, a.TargetSW) {
				return true
			}
		}
	}
	for _, keywordReg := range keywordRegexes {
		if keywordReg.MatchString(result.Vuln.Description) {
			return true
		}
	}
	log.Debugf("Ruby failed validation: %s %s", result.CPE.Product, result.CVE.ID())
	return false
}

func anyContains(s string, tgts ...string) bool {
	for _, t := range tgts {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}
