package extractors

import (
	"io"

	"github.com/stackrox/scanner/pkg/filemap"
)

type Extractor interface {
	ExtractFiles(layer io.ReadCloser, matchers []filemap.Matcher) (filemap.FileMap, error)
}

type DockerExtractor struct {
}

func (d DockerExtractor) ExtractFiles(layer io.ReadCloser, matchers []filemap.Matcher) (filemap.FileMap, error) {
	return filemap.ExtractFiles(layer, matchers)
}
