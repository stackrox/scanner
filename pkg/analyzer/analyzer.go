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

// FilterFuncProducer is a function that takes in package database contents
// and outputs a FilterFunc, finish func, and error.
// The FilterFunc is meant to be used AnalyzeOptions.FilterFn.
// The FinishFunc is meant to be called once the given database is no longer needed.
// It is common for the FilterFunc to require the database to be open while it is used,
// so the finish func should be called once all calls to the FilterFunc have completed.
type FilterFuncProducer func([]byte) (func(string) bool, func(), error)

type AnalyzeOptions struct {
	FilterFn FilterFunc
}

type AnalyzeOption interface {
	apply(*AnalyzeOptions)
}

// FilterFunc takes in a file path and determines if the given file should be ignored by the analyzer.
// It is an additional filter to be used alongside the analyzer's own filtering process.
// When FilterFunc returns true, the file is NOT ignored.
type FilterFunc func(path string) bool

func (f FilterFunc) apply(o *AnalyzeOptions) {
	o.FilterFn = f
}

// WithFilterFunc uses the given function as a FilterFunc.
func WithFilterFunc(f func(path string) bool) AnalyzeOption {
	return FilterFunc(f)
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
		opts.FilterFn = func(_ string) bool {
			return true
		}
	}
}
