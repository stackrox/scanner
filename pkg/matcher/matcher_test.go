package matcher

import (
	"regexp"
	"testing"

	"github.com/stackrox/scanner/pkg/fileinfo/mock"
	"github.com/stretchr/testify/assert"
)

func TestAndMatcher(t *testing.T) {
	// Should not match anything.
	m := NewAndMatcher()
	match, extract := m.Match("/file/path", &mock.FileInfo{}, nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should never be extractable.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), false))
	match, extract = m.Match("Test1", &mock.FileInfo{}, nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail1", &mock.FileInfo{}, nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should only be extractable if there is a match.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), true))
	match, extract = m.Match("Test2", &mock.FileInfo{}, nil)
	assert.True(t, match)
	assert.True(t, extract)
	match, extract = m.Match("Fail2", &mock.FileInfo{}, nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should never be extractable.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile(".*Test"), true), NewWhiteoutMatcher())
	match, extract = m.Match(".wh.Test3", &mock.FileInfo{}, nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail3", &mock.FileInfo{}, nil)
	assert.False(t, match)
	assert.False(t, extract)
}
