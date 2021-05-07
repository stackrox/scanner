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

func Analyze(filesMap tarutil.FilesMap, analyzers []Analyzer, opts ...AnalyzeOption) ([]*component.Component, error) {
	var o AnalyzeOptions
	for _, opt := range opts {
		opt.apply(&o)
	}
	validateOptions(&o)

	var allComponents []*component.Component
	for _, a := range analyzers {
		components, err := a.Analyze(filesMap, o)
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
		opts.FilterFn = func(string) bool {
			return true
		}
	}
}

// WrapAnalyzeWithFilterFuncProducer takes in a FilterFuncProducer and packages database
// and wraps it around a call to Analyze with the FilterFunc option set as the FilterFunc produced by the given producer.
// The returned function acts as a replacement for Analyze.
func WrapAnalyzeWithFilterFuncProducer(producer FilterFuncProducer, db []byte) func(tarutil.FilesMap, []Analyzer, ...AnalyzeOption) ([]*component.Component, error) {
	return func(filesMap tarutil.FilesMap, analyzers []Analyzer, opts ...AnalyzeOption) ([]*component.Component, error) {
		filterFn, finishFn, err := producer(db)
		if err != nil {
			return nil, err
		}
		defer finishFn()

		return Analyze(filesMap, analyzers, append(opts, WithFilterFunc(filterFn))...)
	}
}
