package kernelparser

import "github.com/pkg/errors"

var (
	// ErrKernelUnrecognized indicates the kernel is unrecognized by the parser.
	// Some other parser may still recognize it, though.
	ErrKernelUnrecognized = errors.New("Kernel unrecognized")

	// ErrKernelUnsupported indicates the kernel is unsupported.
	// This is typically used for node scanning when the kernel is unsupported
	// but the other node components may still be supported.
	ErrKernelUnsupported = errors.New("Kernel unsupported")

	// ErrNodeUnsupported indicates the entire node is unsupported.
	// This is typically is used for node scanning when the node is running
	// an OS which is completely unsupported.
	ErrNodeUnsupported = errors.New("Node unsupported")
)
