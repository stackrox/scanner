package istioloader

import (
	"io"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/istio-cves/types"
)

// LoadYAMLFileFromReader loads the Kubernetes CVE feed from the given io.Reader.
// It does NOT close the reader; that is the caller's responsibility.
func LoadYAMLFileFromReader(r io.Reader) (types.Vuln, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return types.Vuln{}, errors.Wrap(err, "reading YAML contents")
	}
	var schema types.Vuln
	if err := yaml.Unmarshal(contents, &schema); err != nil {
		return types.Vuln{}, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return schema, nil
}
