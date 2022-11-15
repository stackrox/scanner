package matcher

import (
	"os"
	"regexp"
	"testing"

	"github.com/stackrox/scanner/pkg/fsutil/fileinfo/mock"
	"github.com/stretchr/testify/assert"
)

func TestPrefixAllowlistMatcher(t *testing.T) {
	// Should not match anything.
	m := NewPrefixAllowlistMatcher()
	match, extract := m.Match("Test", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should match.
	m = NewPrefixAllowlistMatcher("Test", "test")
	match, extract = m.Match("Test", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
	match, extract = m.Match("test", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)

	// Should not match.
	m = NewPrefixAllowlistMatcher("Test", "test")
	match, extract = m.Match("Fail", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
}

func TestWhiteoutMatcher(t *testing.T) {
	m := NewWhiteoutMatcher()

	// Should not match.
	match, extract := m.Match("Fail", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should match whiteout.
	match, extract = m.Match(".wh.Test1", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)

	// Should match opaque directory.
	match, extract = m.Match(".wh..wh..opqTest1", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
}

func TestExecutableMatcher(t *testing.T) {
	m := NewExecutableMatcher()

	// Should not match.
	match, extract := m.Match("Fail", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should match.
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0001)), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0010)), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0011)), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0100)), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0101)), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(0111)), nil)
	assert.True(t, match)
	assert.False(t, extract)
}

func TestRegexpMatcher(t *testing.T) {
	m := NewRegexpMatcher(regexp.MustCompile("Test"), false)
	// Should not match nor be extractable.
	match, extract := m.Match("Fail", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
	// Should match but not extractable.
	match, extract = m.Match("Test", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("HelloTestGoodbye", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)

	m = NewRegexpMatcher(regexp.MustCompile("Test"), true)
	// Should not match nor be extractable.
	match, extract = m.Match("Fail", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
	// Should match and be extractable.
	match, extract = m.Match("Test", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
	match, extract = m.Match("HelloTestGoodbye", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
}

func TestSymboliclinkMatcher(t *testing.T) {
	m := NewSymbolicLinkMatcher()

	// Should not match.
	match, extract := m.Match("Fail1", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail2", mock.NewFileInfo(mock.FileMode(0111)), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should match.
	match, extract = m.Match("Test1", mock.NewFileInfo(mock.FileMode(os.ModeSymlink)), nil)
	assert.True(t, match)
	assert.False(t, extract)
}

func TestOrMatcher(t *testing.T) {
	// Should not match anything.
	m := NewOrMatcher()
	match, extract := m.Match("Fail1", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should never be extractable.
	m = NewOrMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), false))
	match, extract = m.Match("Test1", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail2", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should only be extractable if there is a match.
	m = NewOrMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), true))
	match, extract = m.Match("Test2", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
	match, extract = m.Match("Fail3", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	m = NewOrMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), true), NewRegexpMatcher(regexp.MustCompile("test"), false))
	// Should match and be extractable.
	match, extract = m.Match("Test3", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
	// Should match but not be extractable.
	match, extract = m.Match("test1", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
	// Should not match.
	match, extract = m.Match("Fail3", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
}

func TestAndMatcher(t *testing.T) {
	// Should not match anything.
	m := NewAndMatcher()
	match, extract := m.Match("Fail1", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should never be extractable.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), false))
	match, extract = m.Match("Test1", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail2", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should only be extractable if there is a match.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile("Test"), true))
	match, extract = m.Match("Test2", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.True(t, extract)
	match, extract = m.Match("Fail3", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)

	// Should never be extractable.
	m = NewAndMatcher(NewRegexpMatcher(regexp.MustCompile(".*Test"), true), NewWhiteoutMatcher())
	match, extract = m.Match(".wh.Test3", mock.NewFileInfo(), nil)
	assert.True(t, match)
	assert.False(t, extract)
	match, extract = m.Match("Fail4", mock.NewFileInfo(), nil)
	assert.False(t, match)
	assert.False(t, extract)
}

func Test_findCommonDirPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		want     []string
	}{
		{
			name: "happy case",
			prefixes: []string{
				"bin/[",
				"bin/busybox",
				"etc/alpine-release",
				"etc/apt/sources.list",
				"etc/centos-release",
				"etc/lsb-release",
				"etc/oracle-release",
				"etc/os-release",
				"etc/os-release",
				"etc/redhat-release",
				"etc/system-release",
				"lib/apk/db/installed",
				"root/buildinfo/content_manifests",
				"usr/lib/os-release",
				"var/lib/dpkg/status",
				"var/lib/rpm/Packages",
				"var/lib/rpm/Packages",
			},
			want: []string{
				"bin/",
				"etc/",
				"lib/apk/db/",
				"root/buildinfo/",
				"usr/lib/",
				"var/lib/",
			},
		},
		{
			name: "prefixes with directories",
			prefixes: []string{
				"foo/bar/",
				"foo/bar/ok/",
				"foo/bar/nook/",
				"foo/bar/nook/",
			},
			want: []string{"foo/bar/"},
		},
		{
			name: "non-slash are considered files",
			prefixes: []string{
				"usr/bin",
				"usr/bin/",
			},
			want: []string{"usr/"},
		},
		{
			name: "example from doc comment",
			prefixes: []string{
				"var/lib/rpm/",
				"var/lib/dpkg/",
				"root/buildinfo/",
				"usr/bin",
				"usr/bin/bash",
				"etc/apt.sources",
			},
			want: []string{
				"var/lib/",
				"root/buildinfo/",
				"usr/",
				"etc/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.want, findCommonDirPrefixes(tt.prefixes))
		})
	}
}
