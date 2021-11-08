package requiredfilenames

import (
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurefmt/dpkg"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/matcher"
)

var (
	instance matcher.Matcher
	once     sync.Once
)

// SingletonMatcher returns the singleton matcher instance to use for extracting
// files to be analyzed for operating system features.
// Note: language-level analyzers implement a different interface, and do not require
// extraction of files into a `FileMap`. Therefore, the respective files do not need
// to be matched here.
func SingletonMatcher() matcher.Matcher {
	once.Do(func() {
		allFileNames := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
		clairMatcher := matcher.NewPrefixAllowlistMatcher(allFileNames...)
		whiteoutMatcher := matcher.NewWhiteoutMatcher()
		dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp)
		// All other matchers take precedence over this matcher.
		// For example, an executable python file should be matched by
		// the Python matcher. This matcher should be used for any
		// remaining executable files which went unmatched otherwise.
		// Therefore, this matcher MUST be the last matcher.
		executableMatcher := matcher.NewExecutableMatcher()

		// Note: Order is important. The order of these matchers is the order by which matching is performed.
		allMatchers := []matcher.Matcher{
			clairMatcher,
			whiteoutMatcher,
			dpkgFilenamesMatcher,
			// All other matchers take precedence over this matcher.
			// For example, an executable python file should be matched by
			// the Python matcher. This matcher should be used for any
			// remaining executable files which went unmatched otherwise.
			// Therefore, this matcher MUST be the last matcher.
			executableMatcher,
		}

		instance = matcher.NewOrMatcher(allMatchers...)
	})
	return instance
}
