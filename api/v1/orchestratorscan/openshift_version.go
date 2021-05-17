package orchestratorscan

import (
	"regexp"

	"github.com/pkg/errors"
)

var (
	// Matching version like v3.11.0+48aaaa9-544, detailed later
	version3XRegex = regexp.MustCompile(`^v(3\.11)[+-\.0-9a-f]*$`)
	// Matching version like 4.7.5, detailed later
	version4XRegex = regexp.MustCompile(`^([0-9]+\.[0-9]+)(?:\.[0-9]+)*$`)
)

type openShiftVersion struct {
	version       string
	versionFamily string
}

func newVersion(version string) (*openShiftVersion, error) {
	var matched []string
	matched = version4XRegex.FindStringSubmatch(version)
	if len(matched) == 0 {
		matched = version3XRegex.FindStringSubmatch(version)
	}

	if len(matched) == 0 {
		return nil, errors.Errorf("unrecognized OpenShift version: %s", version)
	}

	return &openShiftVersion{
		version:       version,
		versionFamily: matched[1],
	}, nil
}

func (o *openShiftVersion) GetCPE() string {
	return "cpe:/a:redhat:openshift:" + o.versionFamily
}
