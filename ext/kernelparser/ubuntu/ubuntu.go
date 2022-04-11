package ubuntu

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
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

func parser(db database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, bool, error) {
	if !strings.Contains(osImage, "ubuntu") {
		return nil, false, nil
	}

	matches := regex.FindStringSubmatch(osImage)
	if len(matches) == 0 {
		return nil, false, errors.Errorf("could not find Ubuntu version in OS string: %q", osImage)
	}
	if len(matches) > 1 {
		return nil, false, errors.Errorf("found multiple Ubuntu versions in OS string: %q", osImage)
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
		return nil, false, errors.Errorf("error checking if feature exists: %v", err)
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
	}, true, nil
}

// StripVersionPadding removes the version padding appended to the end of an Ubuntu version.
func StripVersionPadding(version string) string {
	return strings.TrimSuffix(version, versionPadding)
}
