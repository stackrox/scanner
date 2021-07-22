package requiredfilenames

import (
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurefmt/dpkg"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/singletons/analyzers"
)

var (
	instance matcher.Matcher
	once     sync.Once
)

// SingletonMatcher returns the singleton matcher instance to use.
func SingletonMatcher() matcher.Matcher {
	once.Do(func() {
		allFileNames := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
		clairMatcher := matcher.NewPrefixAllowlistMatcher(allFileNames...)
		whiteoutMatcher := matcher.NewWhiteoutMatcher()
		executableMatcher := matcher.NewExecutableMatcher()
		dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp)

		allAnalyzers := analyzers.Analyzers()

		allMatchers := make([]matcher.Matcher, 0, len(allAnalyzers)+4)
		allMatchers = append(allMatchers, clairMatcher, whiteoutMatcher, executableMatcher, dpkgFilenamesMatcher)
		for _, a := range allAnalyzers {
			allMatchers = append(allMatchers, a)
		}

		instance = matcher.NewOrMatcher(allMatchers...)
	})
	return instance
}
