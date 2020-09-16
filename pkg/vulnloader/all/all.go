package all

import (
	// Import all the vulnloader providers.
	_ "github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
	_ "github.com/stackrox/scanner/pkg/vulnloader/redhatloader"
)
