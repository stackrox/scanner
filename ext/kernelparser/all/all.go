package all

import (
	// Import all the kernelparsers
	_ "github.com/stackrox/scanner/ext/kernelparser/amzn"
	_ "github.com/stackrox/scanner/ext/kernelparser/cos"
	_ "github.com/stackrox/scanner/ext/kernelparser/debian"
	_ "github.com/stackrox/scanner/ext/kernelparser/rhel"
	_ "github.com/stackrox/scanner/ext/kernelparser/ubuntu"
)
