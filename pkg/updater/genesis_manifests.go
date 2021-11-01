package updater

import (
	"fmt"

	"github.com/stackrox/rox/pkg/urlfmt"
)

const apiPathInCentral = "api/extensions/scannerdefinitions"

// getRelevantDownloadURL gets the genesis manifests URL.
func getRelevantDownloadURL(centralEndpoint string) string {
	if centralEndpoint == "" {
		centralEndpoint = "https://central.stackrox.svc"
	}
	centralEndpoint = urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)
	return fmt.Sprintf("%s/%s", centralEndpoint, apiPathInCentral)
}
