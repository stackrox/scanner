package dotnetcoreruntime

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockFileInfo struct{}

func (f *mockFileInfo) Name() string {
	return ""
}

func (f *mockFileInfo) Size() int64 {
	return 0
}

func (f *mockFileInfo) Mode() os.FileMode {
	return os.ModeDir
}

func (f *mockFileInfo) ModTime() time.Time {
	return time.Now()
}

// IsDir is just gonna return true. This is the only one we really care about.
func (f *mockFileInfo) IsDir() bool {
	return true
}

func (f *mockFileInfo) Sys() interface{} {
	return nil
}

func TestMatching(t *testing.T) {
	a := Analyzer()
	cs := a.ProcessFile("/usr/share/dotnet/shared/Microsoft.AspNetCore.App/3.1.8/", &mockFileInfo{}, nil)
	assert.Len(t, cs, 1)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.8/", &mockFileInfo{}, nil)
	assert.Len(t, cs, 1)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Hello/3.1.8/", &mockFileInfo{}, nil)
	assert.Empty(t, cs)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Microsoft.NETCore.App/3.1/", &mockFileInfo{}, nil)
	assert.Empty(t, cs)
}
