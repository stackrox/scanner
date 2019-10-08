package driver

import (
	"io"

	"github.com/stackrox/scanner/pkg/analyzers"
	"github.com/stackrox/scanner/pkg/extractors"
	"github.com/stackrox/scanner/pkg/filemap"
	"github.com/stackrox/scanner/pkg/types"
)

func AnalyzeLayerWithExtractor(r io.ReadCloser, extractor extractors.Extractor, analyzers []analyzers.Analyzer) ([]types.Component, error) {
	var matchers []filemap.Matcher
	for _, a := range analyzers {
		matchers = append(matchers, a)
	}
	files, err := extractor.ExtractFiles(r, matchers)
	if err != nil {
		return nil, err
	}
	var allComponents []types.Component
	for _, a := range analyzers {
		components, err := a.Extract(files)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}
	return allComponents, nil
}
