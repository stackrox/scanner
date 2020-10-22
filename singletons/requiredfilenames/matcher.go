package requiredfilenames

import (
	"os"
	"strings"
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/singletons/analyzers"
)

var (
	instance matcher.Matcher
	once     sync.Once
)

type dpkgSubPathMatcher struct{}

func (d *dpkgSubPathMatcher) Match(fullPath string, fileInfo os.FileInfo) bool {
	return strings.HasPrefix(fullPath, "var/lib/dpkg/status.d")
}

// SingletonMatcher returns the singleton matcher instance to use.
func SingletonMatcher() matcher.Matcher {
	once.Do(func() {
		allFileNames := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
		clairMatcher := matcher.NewPrefixWhitelistMatcher(allFileNames...)

		allAnalyzers := analyzers.Analyzers()

		allMatchers := make([]matcher.Matcher, 0, len(allAnalyzers)+2)
		allMatchers = append(allMatchers, clairMatcher)
		allMatchers = append(allMatchers, &dpkgSubPathMatcher{})
		for _, a := range allAnalyzers {
			allMatchers = append(allMatchers, a)
		}

		instance = matcher.NewOrMatcher(allMatchers...)
	})
	return instance
}
