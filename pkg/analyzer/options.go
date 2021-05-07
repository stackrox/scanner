package analyzer

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
