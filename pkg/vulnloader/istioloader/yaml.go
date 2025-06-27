package istioloader

import (
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/istio-cves/types"
	"go.yaml.in/yaml/v3"
)

// LoadYAMLFileFromReader loads the Istio CVE feed from the given io.Reader.
// It does NOT close the reader; that is the caller's responsibility.
func LoadYAMLFileFromReader(r io.Reader) (types.Vuln, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return types.Vuln{}, errors.Wrap(err, "reading YAML contents")
	}
	var vuln types.Vuln
	if err := yaml.Unmarshal(contents, &vuln); err != nil {
		return types.Vuln{}, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return vuln, nil
}
