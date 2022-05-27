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
	instance matcher.Matcher
	once     sync.Once
	// dynamicLibRegexp matches all dynamic libraries.
	dynamicLibRegexp = regexp.MustCompile(`(^|/)(lib|ld-)[^/.-][^/]*\.so(\.[^/.]+)*$`)
	// libraryDirRegexp matches all files under directories where the dynamic libraries are commonly found.
	// This is to filter for symbolic links needed to resolve dynamic library paths.
	libraryDirRegexp = regexp.MustCompile(`^(usr/(local/)?)?lib(32|64)?(/.+|$)`)
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

		allMatchers := make([]matcher.Matcher, 0, 6)
		allMatchers = append(allMatchers, clairMatcher, whiteoutMatcher)

		// Active Vuln Mgmt related matchers.
		dpkgFilenamesMatcher := matcher.NewRegexpMatcher(dpkg.FilenamesListRegexp, true)
		dynamicLibMatcher := matcher.NewRegexpMatcher(dynamicLibRegexp, false)
		libDirSymlinkMatcher := matcher.NewAndMatcher(matcher.NewRegexpMatcher(libraryDirRegexp, false), matcher.NewSymbolicLinkMatcher())
		// All other matchers take precedence over this matcher.
		// For example, an executable python file should be matched by
		// the Python matcher. This matcher should be used for any
		// remaining executable files which went unmatched otherwise.
		// Therefore, this matcher MUST be the last matcher.
		executableMatcher := matcher.NewExecutableMatcher()
		allMatchers = append(allMatchers, dpkgFilenamesMatcher, dynamicLibMatcher, libDirSymlinkMatcher, executableMatcher)

		instance = matcher.NewOrMatcher(allMatchers...)
	})
	return instance
}
