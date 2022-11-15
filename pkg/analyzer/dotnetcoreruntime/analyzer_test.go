package dotnetcoreruntime

import (
	"testing"

	"github.com/stackrox/scanner/pkg/fsutil/fileinfo/mock"
	"github.com/stretchr/testify/assert"
)

func TestMatching(t *testing.T) {
	a := Analyzer()
	cs := a.ProcessFile("/usr/share/dotnet/shared/Microsoft.AspNetCore.App/3.1.8/", mock.NewFileInfo(), nil)
	assert.Len(t, cs, 1)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.8/", mock.NewFileInfo(), nil)
	assert.Len(t, cs, 1)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Hello/3.1.8/", mock.NewFileInfo(), nil)
	assert.Empty(t, cs)
	cs = a.ProcessFile("/usr/share/dotnet/shared/Microsoft.NETCore.App/3.1/", mock.NewFileInfo(), nil)
	assert.Empty(t, cs)
}
