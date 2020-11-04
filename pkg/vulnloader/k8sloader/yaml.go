package k8sloader

import (
	"io"
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/k8s-cves/pkg/validation"
)

func LoadYAMLFileFromReader(r io.Reader) (*validation.CVESchema, error) {
	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "reading YAML contents")
	}
	var schema validation.CVESchema
	if err := yaml.Unmarshal(contents, &schema); err != nil {
		return nil, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return &schema, nil
}

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
