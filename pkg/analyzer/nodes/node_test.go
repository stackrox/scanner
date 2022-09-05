package nodes

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/analyzertest"
	"github.com/stretchr/testify/assert"
)

type matcherMock struct {
	matchFunc func(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (matches bool, extract bool)
}

func (f matcherMock) Match(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (bool, bool) {
	if f.matchFunc == nil {
		return false, false
	}
	return f.matchFunc(fullPath, fileInfo, contents)
}

type dirEntryMock struct {
	name     string
	isDir    bool
	fileMode fs.FileMode
	infoFunc func() (fs.FileInfo, error)
}

func (d dirEntryMock) Name() string {
	return d.name
}

func (d dirEntryMock) IsDir() bool {
	return d.isDir
}

func (d dirEntryMock) Type() fs.FileMode {
	return d.fileMode
}

func (d dirEntryMock) Info() (fs.FileInfo, error) {
	if d.infoFunc != nil {
		return d.infoFunc()
	}
	return nil, nil
}

func Test_filesMap_extractFile(t *testing.T) {
	type args struct {
		fileMatcherMock matcherMock
		path            string
		entryMock       dirEntryMock
	}
	type test struct {
		name         string
		args         args
		wantFileData *fileData
		maxFileSize  int64
		wantErr      assert.ErrorAssertionFunc
	}
	tests := []test{
		{
			name: "when path is dir then do nothing",
			args: args{
				fileMatcherMock: matcherMock{},
				entryMock: dirEntryMock{
					isDir: true,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "when path does not exist then do nothing",
			args: args{
				fileMatcherMock: matcherMock{},
				entryMock: dirEntryMock{
					isDir: false,
					infoFunc: func() (fs.FileInfo, error) {
						return nil, fs.ErrNotExist
					},
				},
			},
			wantFileData: nil,
			wantErr:      assert.NoError,
		},
		{
			name: "when no permission to read file info then ignore error",
			args: args{
				fileMatcherMock: matcherMock{},
				entryMock: dirEntryMock{
					isDir: false,
					infoFunc: func() (fs.FileInfo, error) {
						return nil, fs.ErrPermission
					},
				},
			},
			wantFileData: nil,
			wantErr:      assert.NoError,
		},
		{
			name: "when failed to get file info then return error",
			args: args{
				fileMatcherMock: matcherMock{},
				entryMock: dirEntryMock{
					isDir: false,
					infoFunc: func() (fs.FileInfo, error) {
						return nil, fs.ErrInvalid // randomly picked
					},
				},
			},
			wantFileData: nil,
			wantErr:      assert.Error,
		},
		{
			name: "when file does not match then return nothing",
			args: args{
				fileMatcherMock: matcherMock{
					matchFunc: func(_ string, _ os.FileInfo, _ io.ReaderAt) (bool, bool) {
						return false, false
					},
				},
			},
			wantFileData: nil,
			wantErr:      assert.NoError,
		},
		{
			name:        "when file is extractable and size is bigger then the limit then return nothing",
			maxFileSize: 1, // minimal size set to fail
			args: args{
				fileMatcherMock: matcherMock{
					matchFunc: func(_ string, _ os.FileInfo, _ io.ReaderAt) (bool, bool) {
						return true, true
					},
				},
				entryMock: dirEntryMock{infoFunc: func() (fs.FileInfo, error) {
					ff := analyzertest.NewFakeFile("foobar", []byte("foobar is too big"), 0644)
					return ff.FileInfo(), nil
				}},
			},
			wantFileData: nil,
			wantErr:      assert.NoError,
		},
		{
			name: "when file is extractable then return it",
			args: args{
				fileMatcherMock: matcherMock{
					matchFunc: func(_ string, _ os.FileInfo, _ io.ReaderAt) (bool, bool) {
						return true, true
					},
				},
				entryMock: dirEntryMock{infoFunc: func() (fs.FileInfo, error) {
					ff := analyzertest.NewFakeFile("foobar", []byte{}, 0755)
					return ff.FileInfo(), nil
				}},
			},
			wantFileData: &fileData{
				isExecutable:  true,
				isExtractable: true,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.maxFileSize > 0 {
				prevMaxFileSize := analyzer.GetMaxExtractableFileSize()
				analyzer.SetMaxExtractableFileSize(tt.maxFileSize)
				defer func() {
					analyzer.SetMaxExtractableFileSize(prevMaxFileSize)
				}()
			}
			got, err := extractFile(tt.args.path, tt.args.entryMock, tt.args.fileMatcherMock, nil)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.wantFileData, got)
		})
	}
}

func Test_filesMap_Get(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "testdata")
	type fields struct {
		root      string
		fileMap   map[string]*fileData
		readError error
	}
	tests := []struct {
		name         string
		fields       fields
		path         string
		wantFileData analyzer.FileData
		wantExists   bool
		wantError    error
	}{
		{
			name: "when path not in map then returns does not exist",
			path: "whatever",
		},
		{
			name: "when file is not extractable then returns without content",
			fields: fields{
				root: "",
				fileMap: map[string]*fileData{
					"foo/bar.txt": {
						isExecutable:  true,
						isExtractable: false,
					},
				},
				readError: nil,
			},
			path: "foo/bar.txt",
			wantFileData: analyzer.FileData{
				Executable: true,
			},
			wantExists: true,
		},
		{
			name: "when file is in map and is extractable, should return with contents",
			fields: fields{
				root: filepath.Join(testdata, "rootfs-foo"),
				fileMap: map[string]*fileData{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
					},
				},
				readError: nil,
			},
			path: "etc/redhat-release",
			wantFileData: analyzer.FileData{
				Contents: []byte("Some random red hat release that does not exist (X.Y) (foo bar)\n"),
			},
			wantExists: true,
		},
		{
			name: "when file is in map and is extractable but does not exist, then keep error",
			fields: fields{
				root: filepath.Join(testdata, "rootfs-foo"),
				fileMap: map[string]*fileData{
					"foo/does/not/exist": {
						isExecutable:  false,
						isExtractable: true,
					},
				},
				readError: nil,
			},
			path:         "foo/does/not/exist",
			wantFileData: analyzer.FileData{},
			wantExists:   false,
			wantError:    os.ErrNotExist,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &filesMap{
				root:      tt.fields.root,
				files:     tt.fields.fileMap,
				readError: tt.fields.readError,
			}
			gotFileData, gotExists := n.Get(tt.path)
			assert.Equalf(t, tt.wantFileData, gotFileData, "Get(%v)", tt.path)
			assert.Equalf(t, tt.wantExists, gotExists, "Get(%v)", tt.path)
			if tt.wantError != nil {
				assert.ErrorIs(t, n.readError, tt.wantError)
			} else {
				assert.NoError(t, n.readError)
			}
		})
	}
}

func Test_filesMap_ReadErr(t *testing.T) {
	type fields struct {
		readError error
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "when error is set then return error and reset",
			fields: fields{
				readError: errors.New("foobar"),
			},
			wantErr: assert.Error,
		},
		{
			name:    "when error is not set then return nil",
			fields:  fields{},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &filesMap{
				readError: tt.fields.readError,
			}
			tt.wantErr(t, n.readErr(), "readErr()")
			assert.NoError(t, n.readError)
		})
	}
}
