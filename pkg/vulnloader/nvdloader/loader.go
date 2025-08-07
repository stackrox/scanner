package nvdloader

import (
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader"
)

func init() {
	if env.NVDFeedLoader.Enabled() {
		vulnloader.RegisterLoader(vulndump.NVDDirName, &feedLoader{})
	} else {
		vulnloader.RegisterLoader(vulndump.NVDDirName, &apiLoader{})
	}
}
