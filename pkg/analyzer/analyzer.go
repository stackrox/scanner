package analyzer

import (
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// An Analyzer analyzes images and extracts the components present in them.
type Analyzer interface {
	// TODO: Add options for the function instead of passing it????
	// Analyze takes in files and returns scanned components which are relevant to the
	// analyzer. The relevance is determined by the analyzer itself plus the given function
	Analyze(tarutil.FilesMap, func(path string) bool) ([]*component.Component, error)
	matcher.Matcher
}

func Analyze(filesMap tarutil.FilesMap, f func(path string) bool, analyzers []Analyzer) ([]*component.Component, error) {
	var allComponents []*component.Component
	for _, a := range analyzers {
		components, err := a.Analyze(filesMap, f)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}

	return allComponents, nil
}
