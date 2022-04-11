package kernelparser

import "github.com/pkg/errors"

var (
	// ErrNodeUnsupported indicates the entire node is unsupported.
	// This is typically is used for node scanning when the node is running
	// an OS which is completely unsupported.
	ErrNodeUnsupported = errors.New("Node unsupported")
)
