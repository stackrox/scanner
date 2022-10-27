package common

import (
	"archive/zip"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/vulndump"
)

// OpenGenesisDumpAndExtractManifest opens a zip reader for the given vuln dump, validates it,
// and extracts the manifest from it. Returns an error if the dump is invalid.
// The caller is responsible for closing the returned zip reader.
func OpenGenesisDumpAndExtractManifest(zipPath string) (*zip.ReadCloser, *vulndump.Manifest, error) {
	if filepath.Ext(zipPath) != ".zip" {
		return nil, nil, errors.Errorf("invalid dump %q; expected zip file", zipPath)
	}
	zipR, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "opening zip")
	}
	manifest, err := vulndump.LoadManifestFromDump(&zipR.Reader)
	if err != nil {
		return nil, nil, err
	}
	if !manifest.Since.IsZero() {
		return nil, nil, errors.New("invalid dump: not a genesis dump")
	}
	return zipR, manifest, nil
}
