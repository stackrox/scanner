package ubuntu

import (
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
)

const (
	format         = "dpkg"
	versionPadding = ".10000"
)

var (
	regex = regexp.MustCompile(`[0-9]+\.[0-9]+`)
)

func init() {
	kernelparser.RegisterParser("ubuntu", parser)
}

func parser(db database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, bool) {
	if !strings.Contains(osImage, "ubuntu") {
		return nil, false
	}

	matches := regex.FindStringSubmatch(osImage)
	if len(matches) == 0 {
		log.Infof("could not find Ubuntu version in OS string: %q", osImage)
		return nil, true
	}
	if len(matches) > 1 {
		log.Infof("found multiple Ubuntu versions in OS string: %q", osImage)
		return nil, true
	}

	featureName := "linux"
	if strings.Count(kernelVersion, "-") > 1 {
		after := stringutils.GetAfterLast(kernelVersion, "-")
		// Empty and generic use the basic method of looking for vulns
		// This after case, checks for things like -aws, -azure, -gcp, -gke, etc
		if after != "" && after != kernelVersion {
			kernelVersion = strings.TrimSuffix(kernelVersion, "-"+after)
			if after != "generic" {
				featureName = fmt.Sprintf("linux-%s", after)
			}
		}
	}

	namespace := fmt.Sprintf("ubuntu:%s", matches[0])
	kernelSplit := strings.Split(kernelVersion, ".")

	backportedFeature := fmt.Sprintf("%s-%s.%s", featureName, kernelSplit[0], kernelSplit[1])
	exists, err := db.FeatureExists(namespace, backportedFeature)
	if err != nil {
		log.Errorf("error checking if feature exists: %v", err)
		return nil, false
	}
	if exists {
		featureName = backportedFeature
	}

	// Until we can get the upload number (which may not matter?), append a large upload number to avoid false positives
	// https://wiki.ubuntu.com/Kernel/FAQ
	kernelVersion += versionPadding

	return &kernelparser.ParseMatch{
		Namespace:   namespace,
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true
}

func StripVersionPadding(version string) string {
	return strings.TrimSuffix(version, versionPadding)
}
