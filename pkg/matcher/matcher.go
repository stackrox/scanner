package matcher

import (
	"strings"
)

type Matcher interface {
	Match(fileName string) bool
}

type whitelistMatcher struct {
	whitelist []string
}

func (w *whitelistMatcher) Match(fileName string) bool {
	for _, s := range w.whitelist {
		if strings.HasPrefix(fileName, s) {
			return true
		}
	}
	return false
}

// NewPrefixWhitelistMatcher returns a matcher that matches all filenames which have any
// of the passed paths as a prefix.
func NewPrefixWhitelistMatcher(whitelist ...string) Matcher {
	return &whitelistMatcher{whitelist: whitelist}
}

type orMatcher struct {
	matchers []Matcher
}

func (o *orMatcher) Match(fileName string) bool {
	for _, subMatcher := range o.matchers {
		if subMatcher.Match(fileName) {
			return true
		}
	}
	return false
}

// NewOrMatcher returns a matcher that matches if and only if any of the passed submatchers does.
func NewOrMatcher(subMatchers ...Matcher) Matcher {
	return &orMatcher{matchers: subMatchers}
}
