package requiredfilenames

import (
	"regexp"
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurefmt/dpkg"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/matcher"
)

var (
	osMatcher     matcher.PrefixMatcher
	osMatcherOnce sync.Once

	activeVulnMatcher     matcher.Matcher
	activeVulnMatcherOnce sync.Once

	instance matcher.Matcher
	once     sync.Once

	// dynamicLibRegexp matches all dynamic libraries.
	dynamicLibRegexp = regexp.MustCompile(`(^|/)(lib|ld-)[^/.-][^/]*\.so(\.[^/.]+)*$`)
	// libraryDirRegexp matches all files under directories where the dynamic libraries are commonly found.
	// This is to filter for symbolic links needed to resolve dynamic library paths.
	libraryDirRegexp = regexp.MustCompile(`^(usr/(local/)?)?lib(32|64)?(/.+|$)`)
)

// SingletonOSMatcher returns the singleton matcher instance for extracting files
// for O.S. package analysis.
func SingletonOSMatcher() matcher.PrefixMatcher {
	osMatcherOnce.Do(func() {
		allFileNames := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
		osMatcher = matcher.NewPrefixAllowlistMatcher(allFileNames...)
	})
	return osMatcher
}

// SingletonActiveVulnMatcher returns the singleton matcher instance for
// extracting files for active vulnerability analysis.
func SingletonActiveVulnMatcher() matcher.Matcher {
	activeVulnMatcherOnce.Do(func() {
		dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp, true)
		dynamicLibMatcher := matcher.NewRegexpMatcher(dynamicLibRegexp, false)
		libDirSymlinkMatcher := matcher.NewAndMatcher(matcher.NewRegexpMatcher(libraryDirRegexp, false), matcher.NewSymbolicLinkMatcher())
		// All other matchers take precedence over this matcher.
		// For example, an executable python file should be matched by
		// the Python matcher. This matcher should be used for any
		// remaining executable files which went unmatched otherwise.
		// Therefore, this matcher MUST be the last matcher.
		executableMatcher := matcher.NewExecutableMatcher()
		activeVulnMatcher = matcher.NewOrMatcher(
			dpkgFilenamesMatcher,
			dynamicLibMatcher,
			libDirSymlinkMatcher,
			executableMatcher,
		)
	})
	return activeVulnMatcher
}

// SingletonMatcher returns the singleton matcher instance to use for extracting
// files for analyzing image container. It includes matching for O.S. features
// and active vulnerability. Note: language-level analyzers implement a different
// interface, and do not require extraction of files. Therefore, the respective
// files do not need to be matched here.
func SingletonMatcher() matcher.Matcher {
	once.Do(func() {
		instance = matcher.NewOrMatcher(
			matcher.NewWhiteoutMatcher(),
			SingletonOSMatcher(),
			SingletonActiveVulnMatcher())
	})
	return instance
}
