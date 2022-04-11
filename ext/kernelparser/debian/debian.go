package debian

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
)

const (
	featureName = "linux"
	format      = "dpkg"

	gardenLinux = "debian:11"
)

var (
	regex = regexp.MustCompile(`[0-9]+`)
)

func init() {
	kernelparser.RegisterParser("debian", parser)
}

func parser(_ database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, bool, error) {
	if strings.Contains(osImage, "garden") {
		return &kernelparser.ParseMatch{
			Namespace:   gardenLinux,
			Format:      format,
			FeatureName: featureName,
			Version:     kernelVersion,
		}, true, nil
	}

	if !strings.Contains(osImage, "debian") {
		return nil, false, nil
	}

	matches := regex.FindStringSubmatch(osImage)
	if len(matches) == 0 {
		return nil, false, errors.Errorf("could not find Debian version in OS string: %q", osImage)
	}
	if len(matches) > 1 {
		return nil, true, errors.Errorf("found multiple Debian versions in OS string: %q", osImage)
	}

	return &kernelparser.ParseMatch{
		Namespace:   fmt.Sprintf("debian:%s", matches[0]),
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true, nil
}
