package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	genesisManifestsLocation = "/genesis_manifests.json"

	gsPrefix                = "gs://"

	apiPathInCentral = "api/extensions/scannerdefinitions"
)

type knownGenesisDump struct {
	Timestamp    time.Time `json:"timestamp"`
	DiffLocation string    `json:"diffLocation"`
}

type genesisManifest struct {
	KnownGenesisDumps []knownGenesisDump `json:"knownGenesisDumps"`
}

// getRelevantDownloadURL gets the genesis manifests from the dump, finds the one
// with the highest timestamp, and returns the location for the diff dump from that location.
// This ensures that we get the smallest diff dump that works for this version of scanner.
func getRelevantDownloadURL(config Config) (downloadURL string, isCentral bool, err error) {
	if config.FetchFromCentral {
		centralEndpoint := config.CentralEndpoint
		if centralEndpoint == "" {
			centralEndpoint = "https://central.stackrox"
		}
		centralEndpoint, err = urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)
		if err != nil {
			return "", false, errors.Wrap(err, "normalizing central endpoint")
		}
		return fmt.Sprintf("%s/%s", centralEndpoint, apiPathInCentral), true, nil
	}
	genesisFile, err := os.Open(genesisManifestsLocation)
	if err != nil {
		return "", false, errors.Wrap(err, "opening manifests file")
	}
	defer utils.IgnoreError(genesisFile.Close)

	var manifest genesisManifest
	err = json.NewDecoder(genesisFile).Decode(&manifest)
	if err != nil {
		return "", false, errors.Wrap(err, "JSON-decoding manifest")
	}

	if len(manifest.KnownGenesisDumps) == 0 {
		return "", false, errors.New("invalid manifest, no genesis dumps")
	}

	var mostRecentGenesisDump *knownGenesisDump
	for i, dump := range manifest.KnownGenesisDumps {
		if mostRecentGenesisDump == nil || dump.Timestamp.After(mostRecentGenesisDump.Timestamp) {
			mostRecentGenesisDump = &manifest.KnownGenesisDumps[i]
		}
	}

	diffLoc := mostRecentGenesisDump.DiffLocation
	// Convert a gs:// URL to definitions.stackrox.io
	if !strings.HasPrefix(diffLoc, gsPrefix) {
		return "", false, errors.Errorf("invalid diff location %q: must start with %s", diffLoc, gsPrefix)
	}
	return fmt.Sprintf("https://%s", strings.TrimPrefix(diffLoc, "gs://")), false, nil
}
