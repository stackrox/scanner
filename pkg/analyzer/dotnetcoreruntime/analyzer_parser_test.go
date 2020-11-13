package dotnetcoreruntime

import (
	"io/ioutil"
	"testing"

	"github.com/stackrox/scanner/pkg/component"
	"github.com/stretchr/testify/assert"
)

func TestDepsJSONParsing(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/deps.json")
	assert.NoError(t, err)

	fileMap := map[string][]byte{
		"usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Private.Uri.dll":                      nil,
		"usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Runtime.Handles.dll":                  nil,
		"usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Security.Cryptography.Primitives.dll": nil,
	}

	components := parseDepsFile(fileMap, data)
	expected := []*component.Component{
		{
			Name:       "system.private.uri",
			Version:    "4.0.6.0",
			SourceType: component.DotNetCoreRuntimeSourceType,
			Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Private.Uri.dll",
		},
		{
			Name:       "system.runtime.handles",
			Version:    "4.1.2.0",
			SourceType: component.DotNetCoreRuntimeSourceType,
			Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Runtime.Handles.dll",
		},
		{
			Name:       "system.security.cryptography.primitives",
			Version:    "4.1.2.0",
			SourceType: component.DotNetCoreRuntimeSourceType,
			Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.9/System.Security.Cryptography.Primitives.dll",
		},
	}
	for _, c := range expected {
		assert.Contains(t, components, c)
	}
}
