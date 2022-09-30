package istioloader

import (
	"io"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	validate "github.com/stackrox/istio-cves/validation"
)

// LoadYAMLFileFromReader loads the Kubernetes CVE feed from the given io.Reader.
// It does NOT close the reader; that is the caller's responsibility.
func LoadYAMLFileFromReader(r io.Reader) (validate.Vuln, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return validate.Vuln{}, errors.Wrap(err, "reading YAML contents")
	}
	var schema validate.Vuln
	if err := yaml.Unmarshal(contents, &schema); err != nil {
		return validate.Vuln{}, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return schema, nil
}
