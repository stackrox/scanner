package k8sloader

import (
	"io"
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/k8s-cves/pkg/validation"
)

func LoadYAMLFileFromReader(r io.Reader) (*validation.CVESchema, error) {
	var schema validation.CVESchema
	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "reading YAML contents")
	}
	if err := yaml.Unmarshal(contents, &schema); err != nil {
		return nil, errors.Wrap(err, "unmarshalling YAML from reader")
	}
	return &schema, nil
}

func WriteYAMLFileToWriter(contents *validation.CVESchema, w io.Writer) error {
	contentBytes, err := yaml.Marshal(contents)
	if err != nil {
		return errors.Wrap(err, "marshalling YAML into bytes")
	}
	_, err = w.Write(contentBytes)
	if err != nil {
		return errors.Wrap(err, "writing YAML into writer")
	}
	return nil
}
