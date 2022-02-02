package mock

import (
	"os"
	"time"
)

// fileInfo is a dummy implementation for os.FileInfo.
type fileInfo struct {
	mode os.FileMode
}

// NewFileInfo creates a new mock os.FileInfo.
// By default, the returned *os.FileInfo is a directory.
func NewFileInfo(opts ...FileInfoOption) *fileInfo {
	var o options
	for _, opt := range opts {
		opt.apply(&o)
	}

	mode := os.ModeDir
	if o.mode != 0 {
		mode = o.mode
	}

	return &fileInfo{
		mode: mode,
	}
}

func (f *fileInfo) Name() string {
	return ""
}

func (f *fileInfo) Size() int64 {
	return 0
}

func (f *fileInfo) Mode() os.FileMode {
	return f.mode
}

func (f *fileInfo) ModTime() time.Time {
	return time.Now()
}

func (f *fileInfo) IsDir() bool {
	return f.Mode().IsDir()
}

func (f *fileInfo) Sys() interface{} {
	return nil
}
