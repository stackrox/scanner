package busybox

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/analyzer"
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
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
				"bin/[":       {Contents: []byte(bbContent)},
			}),
		},
		// Invalid busybox version strings.
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContentNoVersion)},
				"bin/[":       {Contents: []byte(bbContentNoVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContentBadVersion)},
				"bin/[":       {Contents: []byte(bbContentBadVersion)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContentPartialVersion)},
				"bin/[":       {Contents: []byte(bbContentPartialVersion)},
			}),
		},
		// Unexpected coreutils or unnexpected files.
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte("something else")},
				"bin/[":       {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
				"bin/[":       {Contents: []byte("something else")},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/busybox": {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"bin/[": {Contents: []byte(bbContent)},
			}),
		},
		// Blocked files.
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/os-release": {},
				"bin/busybox":    {Contents: []byte(bbContent)},
				"bin/[":          {Contents: []byte(bbContent)},
			}),
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/lsb-release": {},
				"bin/busybox":     {Contents: []byte(bbContent)},
				"bin/[":           {Contents: []byte(bbContent)},
			}),
		},
	}
	featurens.TestDetector(t, &detector{}, testData)
}
