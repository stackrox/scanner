package analyzer

import (
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// Analyzer defines the functions for analyzing images and extracting the components present in them.
type Analyzer interface {
	Analyze(tarutil.FilesMap) ([]*component.Component, error)
	matcher.Matcher
}

// Factory is a function that creates a new (potentially stateful) analyzer.
type Factory func() Analyzer

// InstantiateAll instantiates all analyzers from the list of factories.
func InstantiateAll(factories ...Factory) []Analyzer {
	result := make([]Analyzer, 0, len(factories))
	for _, factory := range factories {
		result = append(result, factory())
	}
	return result
}

// Analyze analyzes images and extracts the components present in them.
func Analyze(filesMap tarutil.FilesMap, analyzers []Analyzer) ([]*component.Component, error) {
	var allComponents []*component.Component
	for _, a := range analyzers {
		components, err := a.Analyze(filesMap)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}

	return allComponents, nil
}
