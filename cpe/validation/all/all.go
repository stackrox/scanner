package all

import (
	// Import the source validators
	_ "github.com/stackrox/scanner/cpe/validation/java"
	_ "github.com/stackrox/scanner/cpe/validation/node"
	_ "github.com/stackrox/scanner/cpe/validation/python"
	_ "github.com/stackrox/scanner/cpe/validation/ruby"
)
