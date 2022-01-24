package requiredfilenames

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDynamicLibraryRegex(t *testing.T) {
	assert.True(t, dynamicLibRegexp.MatchString("lib/libxyz.so"))
	assert.True(t, dynamicLibRegexp.MatchString("xyz/lib/libxyz.so.1"))
	assert.True(t, dynamicLibRegexp.MatchString("lib64/xyz/libxyz.so.1"))
	assert.True(t, dynamicLibRegexp.MatchString("lib64/xyz/libxyz.so.1.99"))
	assert.True(t, dynamicLibRegexp.MatchString("libxyz.so.1.99"))
	assert.True(t, dynamicLibRegexp.MatchString("libxyz.so.1.compatible"))

	assert.False(t, dynamicLibRegexp.MatchString("lib/xyz.so"))
	assert.False(t, dynamicLibRegexp.MatchString("lib/libxyz.so.1.99."))
	assert.False(t, dynamicLibRegexp.MatchString("lib.xyz.so.1.99"))
	assert.False(t, dynamicLibRegexp.MatchString("xyz/lib/libxyz.so1.99."))
	assert.False(t, dynamicLibRegexp.MatchString("lib.so.99"))

	assert.True(t, dynamicLibRegexp.MatchString("lib/x86_64-linux-gnu/ld-2.28.so"))
	assert.True(t, dynamicLibRegexp.MatchString("lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
	assert.True(t, dynamicLibRegexp.MatchString("lib/x86_64-linux-gnu/libdl.so.2"))
	assert.True(t, dynamicLibRegexp.MatchString("lib/x86_64-linux-gnu/libdl-2.23.so"))
}

func TestLibraryDirRegex(t *testing.T) {
	assert.True(t, libraryDirRegexp.MatchString("lib"))
	assert.True(t, libraryDirRegexp.MatchString("lib32"))
	assert.True(t, libraryDirRegexp.MatchString("lib64"))
	assert.True(t, libraryDirRegexp.MatchString("lib64/abc"))

	assert.True(t, libraryDirRegexp.MatchString("usr/lib"))
	assert.True(t, libraryDirRegexp.MatchString("usr/lib32"))
	assert.True(t, libraryDirRegexp.MatchString("usr/lib64"))
	assert.True(t, libraryDirRegexp.MatchString("usr/lib32/abc"))

	assert.True(t, libraryDirRegexp.MatchString("usr/local/lib"))
	assert.True(t, libraryDirRegexp.MatchString("usr/local/lib32"))
	assert.True(t, libraryDirRegexp.MatchString("usr/local/lib64"))
	assert.True(t, libraryDirRegexp.MatchString("usr/local/lib/abc/d"))

	assert.False(t, libraryDirRegexp.MatchString("usr/local/abc"))
	assert.False(t, libraryDirRegexp.MatchString("lib/"))
	assert.False(t, libraryDirRegexp.MatchString("/lib/abc"))
	assert.False(t, libraryDirRegexp.MatchString("libxyz/abc"))
	assert.False(t, libraryDirRegexp.MatchString("local/lib64/abc"))
}
