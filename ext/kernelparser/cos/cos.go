package cos

import (
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
)

func init() {
	kernelparser.RegisterParser("cos", parser)
}

func parser(_ database.Datastore, kernelVersion, osImage string) (*kernelparser.ParseMatch, error) {
	if strings.HasSuffix(kernelVersion, "+") && strings.Contains(osImage, "container-optimized") {
		// Google COS kernel is unsupported at this time.
		return nil, kernelparser.ErrKernelUnsupported
	}
	return nil, kernelparser.ErrKernelUnrecognized
}
