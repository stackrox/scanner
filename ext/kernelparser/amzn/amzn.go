package amzn

import (
	"strings"

	"github.com/stackrox/scanner/database"
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

func parser(_ database.Datastore, kernelVersion, _ string) (*kernelparser.ParseMatch, error) {
	if !strings.Contains(kernelVersion, "amzn2") {
		return nil, kernelparser.ErrKernelUnrecognized
	}
	return &kernelparser.ParseMatch{
		Namespace:   namespace,
		Format:      format,
		FeatureName: featureName,
		Version:     kernelVersion,
	}, nil
}
