package all

import (
	// Import all the vulnloader providers.
	_ "github.com/stackrox/scanner/pkg/vulnloader/istioloader"
	_ "github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
	_ "github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
	_ "github.com/stackrox/scanner/pkg/vulnloader/redhatloader"
)
