package amzn

import (
	"strings"

	"github.com/stackrox/scanner/ext/kernelparser"
)

const (
	featureName = "kernel"
	namespace   = "amzn:2"
	format      = "rpm"
)

func init() {
	kernelparser.RegisterParser("amzn", parser)
}

func parser(kernelVersion, _ string) (*kernelparser.ParseMatch, bool) {
	if !strings.Contains(kernelVersion, "amzn2") {
		return nil, false
	}
	return &kernelparser.ParseMatch{
		Namespace:   namespace,
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, true
}
