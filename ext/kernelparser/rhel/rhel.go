package rhel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
)

const (
	featureName = "kernel"
	format      = "rpm"
)

var (
	regex = regexp.MustCompile(`el[0-9]+`)
)

func init() {
	kernelparser.RegisterParser("rhel", parser)
}

func parser(_ database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, bool, error) {
	if !strings.Contains(kernelVersion, "el") {
		return nil, false, nil
	}

	matches := regex.FindStringSubmatch(kernelVersion)
	if len(matches) == 0 {
		return nil, false, fmt.Errorf("could not find RHEL version in kernel version string: %q", osImage)
	}
	if len(matches) > 1 {
		return nil, false, fmt.Errorf("found multiple RHEL versions in kernel version string: %q", osImage)
	}

	return &kernelparser.ParseMatch{
		Namespace:   fmt.Sprintf("centos:%s", strings.TrimPrefix(matches[0], "el")),
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true, nil
}
