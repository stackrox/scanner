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
	// rhcosOSImagePrefix is the prefix by which versions of Red Hat CoreOS follow.
	// Example: Red Hat Enterprise Linux CoreOS 47.84.202203141332-0 (Ootpa)
	// The parser expects osImage to be lowercase, so the pattern is lowercase.
	rhcosOSImagePrefix = `red hat enterprise linux coreos `
	rhelKernelPattern  = regexp.MustCompile(`el[0-9]+`)
)

func init() {
	kernelparser.RegisterParser("rhel", parser)
}

func parser(_ database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, error) {
	if !strings.Contains(kernelVersion, "el") {
		return nil, kernelparser.ErrKernelUnrecognized
	}

	if strings.HasPrefix(osImage, rhcosOSImagePrefix) {
		// Explicitly ignore RHEL CoreOS nodes completely.
		return nil, kernelparser.ErrNodeUnsupported
	}

	matches := rhelKernelPattern.FindStringSubmatch(kernelVersion)
	if len(matches) == 0 {
		return nil, fmt.Errorf("could not find RHEL version in kernel version string: %q", osImage)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("found multiple RHEL versions in kernel version string: %q", osImage)
	}

	return &kernelparser.ParseMatch{
		Namespace:   fmt.Sprintf("centos:%s", strings.TrimPrefix(matches[0], "el")),
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, nil
}
