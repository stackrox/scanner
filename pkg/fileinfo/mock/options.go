package mock

import "os"

type options struct {
	mode os.FileMode
}

// FileInfoOption represents a configuration option for a mock os.FileInfo.
type FileInfoOption interface {
	apply(*options)
}

type fileInfoOption func(*options)

func (f fileInfoOption) apply(o *options) {
	f(o)
}

// FileMode sets the file mode.
func FileMode(mode os.FileMode) FileInfoOption {
	return fileInfoOption(func(o *options) {
		o.mode = mode
	})
}
