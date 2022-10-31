package all

import (
	// Import all the vulnsrc providers EXCEPT for the manual source.
	_ "github.com/stackrox/scanner/ext/vulnsrc/alpine"
	_ "github.com/stackrox/scanner/ext/vulnsrc/amzn"
	_ "github.com/stackrox/scanner/ext/vulnsrc/debian"
	_ "github.com/stackrox/scanner/ext/vulnsrc/rhel"
	_ "github.com/stackrox/scanner/ext/vulnsrc/stackrox"
	_ "github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
)
