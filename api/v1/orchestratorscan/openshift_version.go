package orchestratorscan

import (
	"regexp"
	"strings"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/api/v1/convert"
)

var (
	// Version family is like 3.11, 4.5, 4.7 which defines the versions in the same stream and hence comparable.
	versionFamilyRegex = regexp.MustCompile(`^(3\.11|(?:[4-9]|[1-9][0-9]+)\.[0-9]+)\.[0-9]+`)
	// Version families we can compare directly.
	// Ovals for OpenShift 4.4-current does not have valid patch number in the fixed versions.
	// We will try to extract the fixed version from the title field.
	titleVersionRegex        = regexp.MustCompile(`OpenShift Container Platform ([0-9]+\.[0-9]+(?:\.[0-9]+)?) `)
	qualifiedVersionFamilies = set.StringSet{"4.0": {}, "4.1": {}, "4.2": {}, "4.3": {}, "3.11": {}}
)

type openShiftVersion struct {
	version       rpmVersion.Version
	versionFamily string
}

func newOpenShiftVersion(version string) (*openShiftVersion, error) {
	version = strings.Trim(version, "v")

	matched := versionFamilyRegex.FindStringSubmatch(version)
	if len(matched) != 2 {
		return nil, errors.Errorf("unrecognized OpenShift version: %s", version)
	}
	ver, err := convert.TruncateVersion(version)
	if err != nil {
		return nil, errors.Wrapf(err, "unrecognized OpenShift version %s", version)
	}
	return &openShiftVersion{
		version:       rpmVersion.NewVersion(ver),
		versionFamily: matched[1],
	}, nil
}

// CreateCPE returns the cpe used for search.
func (o *openShiftVersion) CreateCPE() string {
	return "cpe:/a:redhat:openshift:" + o.versionFamily
}

// CreatePkgName creates package name to filter.
func (o *openShiftVersion) CreatePkgName() string {
	pkgName := "openshift-hyperkube"
	if o.versionFamily == "3.11" {
		return "atomic-" + pkgName
	}
	return pkgName
}

// LessThan compares this OpenShift version with version and return true if it is less than version.
func (o *openShiftVersion) LessThan(version rpmVersion.Version) bool {
	return o.version.LessThan(version)
}

// GetFixedVersion extracts a comparable version from (fixedIn, title).
func (o *openShiftVersion) GetFixedVersion(fixedIn string, title string) (string, error) {
	if fixedIn == "" {
		return "", nil
	}

	if qualifiedVersionFamilies.Contains(o.versionFamily) {
		version, err := convert.TruncateVersion(fixedIn)
		if err != nil {
			return "", err
		}
		return version, nil
	}

	if title == "" {
		return "", errors.Errorf("cannot get version from %s", fixedIn)
	}

	version, err := convert.TruncateVersion(title)
	if err != nil {
		// Patch: Get the version from title.
		matched := titleVersionRegex.FindStringSubmatch(title)
		if len(matched) != 2 || !strings.HasPrefix(matched[1], o.versionFamily) {
			return "", errors.Errorf("cannot get version from fixed_in_version %s, or title %s", fixedIn, title)
		}
		version = matched[1]
	}

	// Extra patch, according to the release notes, version 4.5 is 4.5.1 and version 4.6 is 4.6.1
	if version == "4.5" || version == "4.6" {
		version += ".1"
	}
	return version, nil
}
