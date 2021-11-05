package updater

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	genesisManifestsLocation = "/genesis_manifests.json"

	gsPrefix = "gs://"

	apiPathInCentral = "api/extensions/scannerdefinitions"
)

var (
	uuidFmt                   = `[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}`
	uuidPattern               = regexp.MustCompile(uuidFmt)
	legacyDiffLocationPattern = regexp.MustCompile(fmt.Sprintf(`gs://definitions.stackrox.io/%s/diff.zip`, uuidFmt))
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
func getRelevantDownloadURL(centralEndpoint string) (string, error) {
	if centralEndpoint == "" {
		centralEndpoint = "https://central.stackrox.svc"
	}
	centralEndpoint = urlfmt.FormatURL(centralEndpoint, urlfmt.HTTPS, urlfmt.NoTrailingSlash)

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

	diffLoc := mostRecentGenesisDump.DiffLocation
	var uuid string
	if strings.HasPrefix(diffLoc, gsPrefix) {
		// legacy pattern.
		matches := legacyDiffLocationPattern.FindStringSubmatch(diffLoc)
		if len(matches) != 2 {
			return "", errors.Errorf("invalid legacy diff location: %q", diffLoc)
		}
		uuid = matches[1]
	} else {
		// non-legacy pattern.
		if !uuidPattern.MatchString(diffLoc) {
			return "", errors.Errorf("invalid diff location UUID: %q", diffLoc)
		}
		uuid = diffLoc
	}

	fullURL, err := urlfmt.FullyQualifiedURL(path.Join(centralEndpoint, apiPathInCentral), url.Values{
		"uuid": []string{uuid},
	})
	if err != nil {
		return "", errors.Wrap(err, "creating full Central URL")
	}

	return fullURL, nil
}
