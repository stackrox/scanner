package busybox

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
	"testing"
)

func Test_detector_Detect(t *testing.T) {
	randomContent := "foobar"
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{
				Name:          "busybox:1.2.3",
				VersionFormat: language.ParserName,
			},
			Files: tarutil.FilesMap{
				"bin/busybox": tarutil.FileData{Contents: []byte(randomContent)},
				"bin/sh":      tarutil.FileData{Contents: []byte(randomContent)},
				"bin/ls":      tarutil.FileData{Contents: []byte(randomContent)},
			},
		},
		{
			ExpectedNamespace: nil,
			Files: tarutil.FilesMap{
				"etc/os-release": tarutil.FileData{Contents: []byte(randomContent)},
				"bin/busybox":    tarutil.FileData{Contents: []byte(randomContent)},
				"bin/sh":         tarutil.FileData{Contents: []byte(randomContent)},
				"bin/ls":         tarutil.FileData{Contents: []byte(randomContent)},
			},
		},
	}
	featurens.TestDetector(t, &detector{}, testData)
}
