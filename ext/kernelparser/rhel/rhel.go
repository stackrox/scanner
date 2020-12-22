package rhel

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
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

func parser(kernelVersion, osImage string) (*kernelparser.ParseMatch, bool) {
	if !strings.Contains(kernelVersion, "el") {
		return nil, false
	}

	matches := regex.FindStringSubmatch(kernelVersion)
	if len(matches) == 0 {
		log.Infof("could not find RHEL version in kernel version string: %q", osImage)
		return nil, true
	}
	if len(matches) > 1 {
		log.Infof("found multiple RHEL versions in kernel version string: %q", osImage)
		return nil, true
	}

	return &kernelparser.ParseMatch{
		Namespace:   fmt.Sprintf("centos:%s", strings.TrimPrefix(matches[0], "el")),
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true
}
