package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	genesisManifestsLocation = "/genesis_manifests.json"

	gsPrefix                = "gs://"
	storageGoogleAPIsPrefix = "https://storage.googleapis.com/"
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
func getRelevantDownloadURL() (string, error) {
	genesisFile, err := os.Open(genesisManifestsLocation)
	if err != nil {
		return "", errors.Wrap(err, "opening manifests file")
	}
	defer utils.IgnoreError(genesisFile.Close)

	var manifest genesisManifest
	err = json.NewDecoder(genesisFile).Decode(&manifest)
	if err != nil {
		return "", errors.Wrap(err, "JSON-decoding manifest")
	}

	if len(manifest.KnownGenesisDumps) == 0 {
		return "", errors.New("invalid manifest, no genesis dumps")
	}

	var maxTimestamp time.Time
	maxIdx := -1
	for i, dump := range manifest.KnownGenesisDumps {
		if maxIdx == -1 || dump.Timestamp.After(maxTimestamp) {
			maxIdx = i
			maxTimestamp = dump.Timestamp
		}
	}

	diffLoc := manifest.KnownGenesisDumps[maxIdx].DiffLocation
	// Convert a gs:// URL to https://storage.googleapis.com URL.
	if !strings.HasPrefix(diffLoc, gsPrefix) {
		return "", errors.Errorf("invalid diff location %q: must start with %s", diffLoc, gsPrefix)
	}
	return fmt.Sprintf("%s%s", storageGoogleAPIsPrefix, strings.TrimPrefix(diffLoc, "gs://")), nil
}
