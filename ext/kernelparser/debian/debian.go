package debian

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
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

func parser(_ database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, bool) {
	if strings.Contains(osImage, "garden") {
		return &kernelparser.ParseMatch{
			Namespace:   gardenLinux,
			Format:      format,
			FeatureName: featureName,
			Version:     kernelVersion,
		}, true
	}

	if !strings.Contains(osImage, "debian") {
		return nil, false
	}

	matches := regex.FindStringSubmatch(osImage)
	if len(matches) == 0 {
		log.Infof("could not find Debian version in OS string: %q", osImage)
		return nil, true
	}
	if len(matches) > 1 {
		log.Infof("found multiple Debian versions in OS string: %q", osImage)
		return nil, true
	}

	return &kernelparser.ParseMatch{
		Namespace:   fmt.Sprintf("debian:%s", matches[0]),
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true
}
