package mock

import (
	"os"
	"time"
)

// FileInfo is a dummy implementation for os.FileInfo.
type FileInfo struct{}

func (f *FileInfo) Name() string {
	return ""
}

func (f *FileInfo) Size() int64 {
	return 0
}

func (f *FileInfo) Mode() os.FileMode {
	return os.ModeDir
}

func (f *FileInfo) ModTime() time.Time {
	return time.Now()
}

// IsDir just returns true. This is the only one we really care about.
func (f *FileInfo) IsDir() bool {
	return true
}

func (f *FileInfo) Sys() interface{} {
	return nil
}
