package cos

import (
	"strings"

	"github.com/stackrox/scanner/ext/kernelparser"
)

func init() {
	kernelparser.RegisterParser("cos", parser)
}

func parser(kernelVersion, osImage string) (*kernelparser.ParseMatch, bool) {
	if strings.HasSuffix(kernelVersion, "+") && strings.Contains(osImage, "container-optimized") {
		return nil, true
	}
	return nil, false
}
