package requiredfilenames

import (
	"sync"

	"github.com/stackrox/scanner/pkg/analyzer"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurefmt/dpkg"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/matcher"
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

		// Allocate extra spaces for the feature-flagged matchers.
		allMatchers := make([]matcher.Matcher, 0, 4)
		allMatchers = append(allMatchers, clairMatcher, whiteoutMatcher)

		if features.ActiveVulnMgmt.Enabled() {
			dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp)
			// All other matchers take precedence over this matcher.
			// For example, an executable python file should be matched by
			// the Python matcher. This matcher should be used for any
			// remaining executable files which went unmatched otherwise.
			// Therefore, this matcher MUST be the last matcher.
			executableMatcher := matcher.NewExecutableMatcher()

			allMatchers = append(allMatchers, dpkgFilenamesMatcher, executableMatcher)
		}

		instance = matcher.NewCombinedMatcher(allMatchers...)
	})
	return instance
}

// MatcherForAnalyzers returns a matcher that takes all the analyzers as well as the default
// matchers into account.
func MatcherForAnalyzers(analyzers ...analyzer.Analyzer) matcher.Matcher {
	allMatchers := make([]matcher.Matcher, 0, len(analyzers)+1)
	for _, a := range analyzers {
		allMatchers = append(allMatchers, a)
	}
	allMatchers = append(allMatchers, SingletonMatcher())

	return matcher.NewCombinedMatcher(allMatchers...)
}
