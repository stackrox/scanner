package cpeutils

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/pkg/errors"
)

// Note: this must be updated with each new OpenShift release.
const maxKnownOpenShift4MinorVersion = 20

// *** START Regex-related consts/vars. ***

// These must all stay in-sync at all times.
const (
	openshiftVersionIdx = 1
	minorVersionIdx     = 3
	submatchLen         = 5
)

var (
	openshift4CPEPattern = regexp.MustCompile(`^cpe:/a:redhat:openshift:(?P<openshiftVersion>4(\.(?P<minorVersion>\d+))?)(::el[7-9])?$`)
)

// *** END Regex-related consts/vars. ***

// GetMostSpecificCPE deterministically returns the CPE that is the most specific
// from the set of matches. This function requires that len(cpes) > 0
func GetMostSpecificCPE(cpes []wfn.AttributesWithFixedIn) wfn.AttributesWithFixedIn {
	mostSpecificCPE := cpes[0]
	for _, cpe := range cpes[1:] {
		if compareAttributes(cpe, mostSpecificCPE) > 0 {
			mostSpecificCPE = cpe
		}
	}
	return mostSpecificCPE
}

func compareAttributes(c1, c2 wfn.AttributesWithFixedIn) int {
	if cmp := strings.Compare(c1.Vendor, c2.Vendor); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(c1.Product, c2.Product); cmp != 0 {
		return cmp
	}
	return strings.Compare(c1.Version, c2.Version)
}

// IsOpenShiftCPE determines whether the passed CPE is an OpenShift CPE.
func IsOpenShiftCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:/a:redhat:openshift:")
}

// IsOpenShift4CPE determines whether the passed CPE is an OpenShift 4 CPE.
func IsOpenShift4CPE(cpe string) bool {
	// This should be faster than performing regex matching.
	return strings.HasPrefix(cpe, "cpe:/a:redhat:openshift:4")
}

// GetAllOpenShift4CPEs returns a slice of other CPEs related to the given Red Hat OpenShift 4 CPE.
// For example, given "cpe:/a:redhat:openshift:4.2", this returns
// ["cpe:/a:redhat:openshift:4.0", "cpe:/a:redhat:openshift:4.1", "cpe:/a:redhat:openshift:4.2"].
// If the CPE does not contain minor-version information,
// then all known minor versions are returned.
func GetAllOpenShift4CPEs(cpe string) ([]string, error) {
	match := openshift4CPEPattern.FindStringSubmatch(cpe)
	if len(match) != submatchLen {
		return nil, errors.Errorf("CPE %s does not match an expected OpenShift 4 CPE format", cpe)
	}

	// We do *not* use the explicit given minor version due to issues with the OVAL data
	// (see https://issues.redhat.com/browse/SECDATA-869 for more information).
	// We just use an arbitrarily high version to ensure it works more consistently.
	maxMinorVersion := maxKnownOpenShift4MinorVersion

	openshiftVersion := match[openshiftVersionIdx]
	cpes := make([]string, 0, maxMinorVersion)
	for i := 0; i <= maxMinorVersion; i++ {
		version := strconv.Itoa(i)
		cpes = append(cpes, strings.Replace(cpe, openshiftVersion, "4."+version, 1))
	}
	return cpes, nil
}
