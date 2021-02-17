package windows

import (
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
)

func init() {
	kernelparser.RegisterParser("windows", parser)
}

func parser(_ database.Datastore, _, osImage string) (*kernelparser.ParseMatch, bool, error) {
	if strings.Contains(osImage, "windows") {
		return nil, true, nil
	}
	return nil, false, nil
}
