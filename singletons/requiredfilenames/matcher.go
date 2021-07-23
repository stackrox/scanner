package requiredfilenames

import (
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurefmt/dpkg"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/features"
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

		allAnalyzers := analyzers.Analyzers()

		// Allocate 2 extra spaces for the feature-flagged matchers.
		allMatchers := make([]matcher.Matcher, 0, len(allAnalyzers)+4)
		allMatchers = append(allMatchers, clairMatcher, whiteoutMatcher)
		for _, a := range allAnalyzers {
			allMatchers = append(allMatchers, a)
		}

		if features.ActiveVulnMgmt.Enabled() {
			executableMatcher := matcher.NewExecutableMatcher()
			dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp)

			allMatchers = append(allMatchers, executableMatcher, dpkgFilenamesMatcher)
		}

		instance = matcher.NewOrMatcher(allMatchers...)
	})
	return instance
}
