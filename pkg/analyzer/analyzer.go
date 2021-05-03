package analyzer

import (
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// An Analyzer analyzes images and extracts the components present in them.
type Analyzer interface {
	Analyze(tarutil.FilesMap, AnalyzeOptions) ([]*component.Component, error)
	matcher.Matcher
}

type FilterFunc func(path string) bool

type AnalyzeOptions struct {
	// FilterFn takes in a file path and determines if the given file should be ignored by the analyzer.
	// It is an additional filter to be used alongside the analyzer's own filtering process.
	// When FilterFn returns true, the file is NOT ignored.
	FilterFn FilterFunc
}

// Not takes in a FilterFunc and returns another FilterFunc
// which would return the inverse for the given func.
func Not(f FilterFunc) FilterFunc {
	return func(path string) bool {
		return !f(path)
	}
}

func Analyze(filesMap tarutil.FilesMap, analyzers []Analyzer, opts AnalyzeOptions) ([]*component.Component, error) {
	validateOptions(&opts)

	var allComponents []*component.Component
	for _, a := range analyzers {
		components, err := a.Analyze(filesMap, opts)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}

	return allComponents, nil
}

func validateOptions(opts *AnalyzeOptions) {
	if opts.FilterFn == nil {
		// Default to always allow.
		opts.FilterFn = func(_ string) bool {
			return true
		}
	}
}
