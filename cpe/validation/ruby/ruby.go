package ruby

import (
	"fmt"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/stringhelpers"
)

type pair struct {
	vendor, product string
}

var (
	knownRubyPkgs = set.NewFrozenStringSet("webrick", "sprockets", "sinatra", "devise")

	// The CVEs related to theforeman:foreman should not be evaluated at this point. It is generally installed
	// via a package manager and any issues should be reflected as part of OS vulns
	disallowedPackages = []pair{
		{
			vendor:  "theforeman",
			product: "foreman",
		},
	}

	disallowedVulns = set.NewStringSet(
		// This CVE entry is malformed and relies on people using very old versions of ruby
		"CVE-2008-1145",
	)

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
	if disallowedVulns.Contains(result.CVE.ID()) {
		return false
	}
	if knownRubyPkgs.Contains(result.CPE.Product) {
		return true
	}
	for _, disallowedPair := range disallowedPackages {
		if result.CPE.Vendor == disallowedPair.vendor && result.CPE.Product == disallowedPair.product {
			return false
		}
	}

	// Check if the vuln matches Ruby in the targetSW
	for _, a := range result.CVE.Config() {
		for _, k := range knownKeywords {
			if stringhelpers.AnyContain([]string{a.Vendor, a.Product, a.TargetSW}, k) {
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
