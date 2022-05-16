package updater

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
	uuidPkg "github.com/stackrox/rox/pkg/uuid"
)

const (
	genesisManifestsLocation = "/genesis_manifests.json"

	apiPathInCentral = "api/extensions/scannerdefinitions"
)

type knownGenesisDump struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      string    `json:"uuid"`
}

type genesisManifest struct {
	KnownGenesisDumps []knownGenesisDump `json:"knownGenesisDumps"`
}

// getMostRecentGenesisDumpUUID opens the genesis manifest file and returns the
// UUID of the most recent genesis dump.
func getMostRecentGenesisDumpUUID() (string, error) {
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
	var mostRecentGenesisDump *knownGenesisDump
	for i, dump := range manifest.KnownGenesisDumps {
		if mostRecentGenesisDump == nil || dump.Timestamp.After(mostRecentGenesisDump.Timestamp) {
			mostRecentGenesisDump = &manifest.KnownGenesisDumps[i]
		}
	}
	uuid := mostRecentGenesisDump.UUID
	if err := validateUUID(uuid); err != nil {
		return "", err
	}
	return uuid, err
}

// getRelevantDownloadURL gets the genesis manifests from the dump, finds the one
// with the highest timestamp, and returns the location for the diff dump from that location.
// This ensures that we get the smallest diff dump that works for this version of scanner.
func getRelevantDownloadURL(centralEndpoint string) (string, error) {
	centralEndpoint = urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)

	uuid, err := getMostRecentGenesisDumpUUID()
	if err != nil {
		return "", errors.Wrap(err, "getting genesis UUID")
	}

	fullURL, err := getURL(centralEndpoint, uuid)
	if err != nil {
		return "", errors.Wrap(err, "creating full Central URL")
	}

	return fullURL, nil
}

func validateUUID(uuid string) error {
	_, err := uuidPkg.FromString(uuid)
	return err
}

func getURL(centralEndpoint, uuid string) (string, error) {
	return urlfmt.FullyQualifiedURL(strings.Join([]string{centralEndpoint, apiPathInCentral}, "/"), url.Values{
		"uuid": []string{uuid},
	})
}
