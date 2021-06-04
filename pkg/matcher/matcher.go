package matcher

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/stackrox/scanner/pkg/whiteout"
)

// Matcher defines the functions necessary for matching files.
type Matcher interface {
	Match(fullPath string, fileInfo os.FileInfo) bool
}

type allowlistMatcher struct {
	allowlist []string
}

func (w *allowlistMatcher) Match(fullPath string, _ os.FileInfo) bool {
	for _, s := range w.allowlist {
		if strings.HasPrefix(fullPath, s) {
			return true
		}
	}
	return false
}

// NewPrefixAllowlistMatcher returns a matcher that matches all filenames which have any
// of the passed paths as a prefix.
func NewPrefixAllowlistMatcher(allowlist ...string) Matcher {
	return &allowlistMatcher{allowlist: allowlist}
}

type whiteoutMatcher struct{}

func (w *whiteoutMatcher) Match(fullPath string, _ os.FileInfo) bool {
	basePath := filepath.Base(fullPath)
	return strings.HasPrefix(basePath, whiteout.Prefix)
}

// NewWhiteoutMatcher returns a matcher that matches all whiteout files
// (ie files which have been deleted).
func NewWhiteoutMatcher() Matcher {
	return &whiteoutMatcher{}
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
