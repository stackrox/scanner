package k8sloader

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

// WriteYAMLFileToWriter marshals the given Kubernetes CVE file as YAML and writes it to the given io.Writer.
// The writer is NOT closed; that is the caller's responsibility.
func WriteYAMLFileToWriter(contents *validation.CVESchema, w io.Writer) error {
	contentBytes, err := yaml.Marshal(contents)
	if err != nil {
		return errors.Wrap(err, "marshaling YAML into bytes")
	}
	_, err = w.Write(contentBytes)
	if err != nil {
		return errors.Wrap(err, "writing YAML into writer")
	}
	return nil
}
