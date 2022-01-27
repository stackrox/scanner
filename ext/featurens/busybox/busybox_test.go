package busybox

import (
	"reflect"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func Test_detector_Detect(t *testing.T) {
	const (
		bbContent               = "yadda yadda BusyBox v1.2.3.git yadda"
		bbContentBadVersion     = "foo Busybox vbar"
		bbContentNoVersion      = "busybox"
		bbContentPartialVersion = "foo Busybox v1.2"
		expectedName            = "busybox:1.2.3"
	)
	testData := []featurens.TestData{
		{
			// Happy Case.
			ExpectedNamespace: &database.Namespace{
				Name:          expectedName,
				VersionFormat: language.ParserName,
			},
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
				"bin/sh":      {Contents: []byte(bbContent)},
			}),
		},
		// Busybox, but failed to parse the version.
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContentNoVersion)},
				"bin/sh":      {Contents: []byte(bbContentNoVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContentBadVersion)},
				"bin/sh":      {Contents: []byte(bbContentBadVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContentPartialVersion)},
				"bin/sh":      {Contents: []byte(bbContentPartialVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte("something else")},
				"bin/sh":      {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
				"bin/sh":      {Contents: []byte("something else")},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/sh": {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"etc/os-release": {},
				"bin/busybox":    {},
				"bin/sh":         {},
				"bin/[":          {},
			}),
		},
	}
	featurens.TestDetector(t, &detector{}, testData)
}

func Test_detector_RequiredFilenames(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{
			name: "required files",
			want: []string{"bin/[", "bin/sh", "bin/busybox"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := detector{}
			if got := de.RequiredFilenames(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RequiredFilenames() = %v, want %v", got, tt.want)
			}
		})
	}
}
