package istioloader

import (
	"io"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/k8s-cves/pkg/validation"
)

// LoadYAMLFileFromReader loads the Kubernetes CVE feed from the given io.Reader.
// It does NOT close the reader; that is the caller's responsibility.
func LoadYAMLFileFromReader(r io.Reader) (*validation.CVESchema, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "reading YAML contents")
	}
	var schema validation.CVESchema
	if err := yaml.Unmarshal(contents, &schema); err != nil {
		return nil, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return &schema, nil
}
