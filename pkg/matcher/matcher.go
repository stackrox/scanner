package matcher

import (
	"os"
	"strings"
)

type Matcher interface {
	Match(fullPath string, fileInfo os.FileInfo) bool
}

type whitelistMatcher struct {
	whitelist []string
}

func (w *whitelistMatcher) Match(fullPath string, _ os.FileInfo) bool {
	for _, s := range w.whitelist {
		if strings.HasPrefix(fullPath, s) {
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

func (o *orMatcher) Match(fullPath string, fileInfo os.FileInfo) bool {
	for _, subMatcher := range o.matchers {
		if subMatcher.Match(fullPath, fileInfo) {
			return true
		}
	}
	return false
}

// NewOrMatcher returns a matcher that matches if and only if any of the passed submatchers does.
func NewOrMatcher(subMatchers ...Matcher) Matcher {
	return &orMatcher{matchers: subMatchers}
}
