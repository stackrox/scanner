package busybox

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func Test_detector_Detect(t *testing.T) {
	const (
		bbContent          = "yadda yadda BusyBox v1.2.3.git yadda"
		expectedName       = "busybox:1.2.3"
		bbContentNoVersion = "busybox"
	)
	testData := []featurens.TestData{
		{
			// Happy Case.
			ExpectedNamespace: &database.Namespace{
				Name:          expectedName,
				VersionFormat: language.ParserName,
			},
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": tarutil.FileData{Contents: []byte(bbContent)},
				"bin/sh":      tarutil.FileData{Contents: []byte(bbContent)},
			}),
		},
		{
			// Busybox, but failed to parse the version.
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": tarutil.FileData{Contents: []byte(bbContentNoVersion)},
				"bin/sh":      tarutil.FileData{Contents: []byte(bbContentNoVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": tarutil.FileData{Contents: []byte("something else")},
				"bin/sh":      tarutil.FileData{Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": tarutil.FileData{Contents: []byte(bbContent)},
				"bin/sh":      tarutil.FileData{Contents: []byte("something else")},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/busybox": tarutil.FileData{Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"bin/sh": tarutil.FileData{Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]tarutil.FileData{
				"etc/os-release": tarutil.FileData{},
				"bin/busybox":    tarutil.FileData{},
				"bin/sh":         tarutil.FileData{},
				"bin/[":          tarutil.FileData{},
			}),
		},
	}
	featurens.TestDetector(t, &detector{}, testData)
}
