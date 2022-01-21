package busybox

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func Test_detector_Detect(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{
				Name:          "busybox:v1.2.3",
				VersionFormat: language.ParserName,
			},
			Files: tarutil.FilesMap{
				"bin/[":       tarutil.FileData{Contents: []byte("yadda yadda BusyBox v1.2.3.git")},
				"bin/busybox": tarutil.FileData{LinkName: "bin/["},
				"bin/sh":      tarutil.FileData{LinkName: "bin/["},
			},
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.FilesMap{
				"etc/os-release": tarutil.FileData{},
				"bin/busybox":    tarutil.FileData{},
				"bin/sh":         tarutil.FileData{},
				"bin/[":          tarutil.FileData{},
			},
		},
	}
	featurens.TestDetector(t, &detector{}, testData)
}
