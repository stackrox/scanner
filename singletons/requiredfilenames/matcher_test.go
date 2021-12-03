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
}
