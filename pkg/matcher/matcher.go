package matcher

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/pkg/whiteout"
)

// Matcher defines the functions necessary for matching files.
type Matcher interface {
	// Match determines if the given file, identified by the given path and info,
	// matches.
	// The first return indicates if it matches.
	// The second return indicates if the contents of the file should be saved (if the first value is true).
	Match(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (matches bool, extract bool)
}

type allowlistMatcher struct {
	allowlist []string
}

func (w *allowlistMatcher) Match(fullPath string, _ os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	for _, s := range w.allowlist {
		if strings.HasPrefix(fullPath, s) {
			return true, true
		}
	}
	return false, true
}

// NewPrefixAllowlistMatcher returns a matcher that matches all filenames which have any
// of the passed paths as a prefix.
func NewPrefixAllowlistMatcher(allowlist ...string) Matcher {
	return &allowlistMatcher{allowlist: allowlist}
}

type whiteoutMatcher struct{}

func (w *whiteoutMatcher) Match(fullPath string, _ os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	basePath := filepath.Base(fullPath)
	return strings.HasPrefix(basePath, whiteout.Prefix), false
}

// NewWhiteoutMatcher returns a matcher that matches all whiteout files
// (ie files which have been deleted).
func NewWhiteoutMatcher() Matcher {
	return &whiteoutMatcher{}
}

type executableMatcher struct{}

func (e *executableMatcher) Match(_ string, fi os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	return fi.Mode().IsRegular() && fi.Mode()&0111 != 0, false
}

// NewExecutableMatcher returns a matcher that matches all executable regular files.
func NewExecutableMatcher() Matcher {
	return &executableMatcher{}
}

type regexpMatcher struct {
	expr *regexp.Regexp
}

func (r *regexpMatcher) Match(fullPath string, _ os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	return r.expr.MatchString(fullPath), true
}

// NewRegexpMatcher returns a matcher that matches all files which adhere to the given regexp pattern.
func NewRegexpMatcher(expr *regexp.Regexp) Matcher {
	return &regexpMatcher{
		expr: expr,
	}
}

type orMatcher struct {
	matchers []Matcher
}

func (o *orMatcher) Match(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (matches bool, extract bool) {
	for _, subMatcher := range o.matchers {
		if matches, extractable := subMatcher.Match(fullPath, fileInfo, contents); matches {
			return true, extractable
		}
	}
	return false, false
}

// NewOrMatcher returns a matcher that matches if and only if any of the passed submatchers does.
func NewOrMatcher(subMatchers ...Matcher) Matcher {
	return &orMatcher{matchers: subMatchers}
}

type symlinkMatcher struct{}

func (o *symlinkMatcher) Match(fullPath string, fileInfo os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	if fileInfo.Mode()&fs.ModeSymlink != 0 {
		return true, false
	}
	return false, false
}

// NewSymbolicLinkMatcher returns a matcher that matches symbolic links
func NewSymbolicLinkMatcher(subMatchers ...Matcher) Matcher {
	return &symlinkMatcher{}
}

type andMatcher struct {
	matchers []Matcher
}

func (a *andMatcher) Match(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (matches bool, extract bool) {
	extract = true
	for _, subMatcher := range a.matchers {
		match, extractable := subMatcher.Match(fullPath, fileInfo, contents)
		if !match {
			return false, false
		}
		extract = extract && extractable
	}
	return true, extract
}

// NewAndMatcher returns a matcher that matches if all the passed submatchers match.
func NewAndMatcher(subMatchers ...Matcher) Matcher {
	return &andMatcher{matchers: subMatchers}
}
