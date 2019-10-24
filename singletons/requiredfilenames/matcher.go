package requiredfilenames

import (
	"sync"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurens"
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
		instance = matcher.NewPrefixWhitelistMatcher(allFileNames...)
	})
	return instance
}
