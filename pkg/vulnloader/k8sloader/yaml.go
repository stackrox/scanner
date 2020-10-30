package k8sloader

import (
	"io"
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

func LoadYAMLFileFromReader(r io.Reader) (*KubernetesCVEFeedYAML, error) {
	var feed KubernetesCVEFeedYAML
	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "reading YAML contents")
	}
	if err := yaml.Unmarshal(contents, &feed); err != nil {
		return nil, errors.Wrap(err, "unmarshaling YAML from reader")
	}
	return &feed, nil
}

func WriteYAMLFileToWriter(contents *KubernetesCVEFeedYAML, w io.Writer) error {
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
