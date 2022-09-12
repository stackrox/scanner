package analyzertest

import (
	"bytes"
	"io"
	"os"
	"path"
	"time"
)

// FakeFile is a fake file for testing purposes.
type FakeFile interface {
	FullPath() string
	FileInfo() os.FileInfo
	Contents() io.ReaderAt
}

// NewFakeFile creates a new fake file from the given path and contents.
func NewFakeFile(fullPath string, contents []byte, mode os.FileMode) FakeFile {
	return fakeFile{
		fullPath: fullPath,
		contents: contents,
		mode:     mode,
	}
}

type fakeFile struct {
	fullPath string
	contents []byte
	mode     os.FileMode
}

func (f fakeFile) FullPath() string {
	return f.fullPath
}

func (f fakeFile) FileInfo() os.FileInfo {
	return f
}

func (f fakeFile) Contents() io.ReaderAt {
	return bytes.NewReader(f.contents)
}

func (f fakeFile) Name() string {
	return path.Base(f.fullPath)
}

func (f fakeFile) Mode() os.FileMode {
	return f.mode
}

func (f fakeFile) IsDir() bool {
	return false
}

func (f fakeFile) Sys() interface{} {
	return nil
}

func (f fakeFile) Size() int64 {
	return int64(len(f.contents))
}

func (f fakeFile) ModTime() time.Time {
	return time.Now()
}
