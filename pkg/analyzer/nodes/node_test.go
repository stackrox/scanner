package nodes

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/analyzertest"
	"github.com/stackrox/scanner/singletons/requiredfilenames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		wantFileData *fileMetadata
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
			name:        "when file is extractable and size is bigger than the limit then return nothing",
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
			wantFileData: &fileMetadata{
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
	testDataRoot := makeTestData(t)

	type fields struct {
		root      string
		fileMap   map[string]*fileMetadata
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
				fileMap: map[string]*fileMetadata{
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
				root: filepath.Join(testDataRoot, "rootfs-foo"),
				fileMap: map[string]*fileMetadata{
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
				root: filepath.Join(testDataRoot, "rootfs-foo"),
				fileMap: map[string]*fileMetadata{
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
		{
			name: "when file is in map, is extractable, and is an absolute symlink, should return with contents",
			fields: fields{
				root: filepath.Join(testDataRoot, "rootfs-rhcos"),
				fileMap: map[string]*fileMetadata{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     true,
					},
				},
				readError: nil,
			},
			path: "etc/redhat-release",
			wantFileData: analyzer.FileData{
				Contents: []byte("Red Hat Enterprise Linux CoreOS release 4.11\n"),
			},
			wantExists: true,
		},
		{
			name: "when file is in map, is extractable, and is a relative symlink, should return with contents",
			fields: fields{
				root: filepath.Join(testDataRoot, "rootfs-rhcos-rel-symlink"),
				fileMap: map[string]*fileMetadata{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     true,
					},
				},
				readError: nil,
			},
			path: "etc/redhat-release",
			wantFileData: analyzer.FileData{
				Contents: []byte("Hello"),
			},
			wantExists: true,
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

func Test_extractFilesFromDirectory(t *testing.T) {
	testDataRoot := makeTestData(t)

	fooRoot := filepath.Join(testDataRoot, "rootfs-foo")
	rhcosRoot := filepath.Join(testDataRoot, "rootfs-rhcos")
	symlinkRelRoot := filepath.Join(testDataRoot, "rootfs-rhcos-rel-symlink")

	testcases := []struct {
		name             string
		root             string
		expectedFilesMap *filesMap
	}{
		{
			name: "etc/redhat-release no symlink",
			root: fooRoot,
			expectedFilesMap: &filesMap{
				root: fooRoot,
				files: map[string]*fileMetadata{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     false,
					},
				},
				readError: nil,
			},
		},
		{
			name: "etc/redhat-release with absolute symlink",
			root: rhcosRoot,
			expectedFilesMap: &filesMap{
				root: rhcosRoot,
				files: map[string]*fileMetadata{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     true,
					},
					"usr/share/buildinfo/content_manifest.json": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     false,
					},
				},
				readError: nil,
			},
		},
		{
			name: "etc/redhat-release with relative symlink",
			root: symlinkRelRoot,
			expectedFilesMap: &filesMap{
				root: symlinkRelRoot,
				files: map[string]*fileMetadata{
					"etc/redhat-release": {
						isExecutable:  false,
						isExtractable: true,
						isSymlink:     true,
					},
				},
				readError: nil,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			filesMap, err := extractFilesFromDirectory(context.Background(), testcase.root, requiredfilenames.SingletonOSMatcher())
			assert.NoError(t, err)
			assert.NoError(t, filesMap.readError)

			assert.Equal(t, testcase.expectedFilesMap.root, filesMap.root)
			assert.Len(t, filesMap.files, len(testcase.expectedFilesMap.files))
			for expectedPath, expectedMetadata := range testcase.expectedFilesMap.files {
				metadata, hasFile := filesMap.files[expectedPath]
				assert.True(t, hasFile)
				assert.NotNil(t, metadata)
				assert.Equal(t, *expectedMetadata, *metadata)
			}
		})
	}
}

func Test_extractFilesFromDirectory_Context(t *testing.T) {
	testDataRoot := makeTestData(t)
	testcases := []struct {
		name            string
		root            string
		ctxDeadline     time.Duration
		expectedErr     error
		expectNilResult bool
	}{
		{
			name:            "context cancellation should return early with error",
			root:            testDataRoot,
			ctxDeadline:     5 * time.Microsecond,
			expectedErr:     context.DeadlineExceeded,
			expectNilResult: true,
		},
		{
			name:            "function should return before context deadline",
			root:            testDataRoot,
			ctxDeadline:     5 * time.Second,
			expectedErr:     nil,
			expectNilResult: false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testcase.ctxDeadline)
			filesMap, err := extractFilesFromDirectory(ctx, testcase.root, requiredfilenames.SingletonOSMatcher())
			cancel()
			assert.ErrorIs(t, err, testcase.expectedErr)
			if testcase.expectNilResult {
				assert.Nil(t, filesMap)
			} else {
				assert.NotNil(t, filesMap)
			}
		})
	}
}

func makeTestData(t *testing.T) string {
	mkdirs := func(file string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0755))
	}
	write := func(file, data string) {
		require.NoError(t, os.WriteFile(file, []byte(data), 0644))
	}

	root := t.TempDir()

	fooRedhatRelease := filepath.Join(root, "rootfs-foo/etc/redhat-release")
	mkdirs(fooRedhatRelease)
	write(fooRedhatRelease, "Some random red hat release that does not exist (X.Y) (foo bar)\n")

	// This directory structure mirrors what we have found in RHCOS 4.11.
	//
	// * `usr/lib/system-release` contains the distro identification data.
	// * `etc/redhat-release` is a symlink to `/usr/lib/system-release`.
	// * `usr/share/buildinfo` contains content manifest json.
	//
	//    $ ls -l etc/redhat-release
	//    total 0
	//    lrwxr-xr-x  1 <OWNER>  <GROUP>  <DATE> redhat-release -> /usr/lib/system-release
	//
	rhcosRedhatRelease := filepath.Join(root, "rootfs-rhcos/etc/redhat-release")
	mkdirs(rhcosRedhatRelease)
	require.NoError(t, os.Symlink("/usr/lib/system-release", rhcosRedhatRelease))

	rhcosSystemRelease := filepath.Join(root, "rootfs-rhcos/usr/lib/system-release")
	mkdirs(rhcosSystemRelease)
	write(rhcosSystemRelease, "Red Hat Enterprise Linux CoreOS release 4.11\n")

	contentManifestJSON := filepath.Join(root, "rootfs-rhcos/usr/share/buildinfo/content_manifest.json")
	mkdirs(contentManifestJSON)
	write(contentManifestJSON, `{"content_sets": ["foo", "bar"]}`)

	// This directory structure mirrors what we have found in RHCOS 4.11
	// except it uses a symlink to a relative path.
	//
	// * `release` contains the data.
	// * `etc/redhat-release` is a symlink to `release`
	//
	//    $ ls -l etc/redhat-release
	//    total 0
	//    lrwxr-xr-x  1 <OWNER>  <GROUP>  <DATE> redhat-release -> ../release
	//
	relSymlinkRedhatRelease := filepath.Join(root, "rootfs-rhcos-rel-symlink/etc/redhat-release")
	mkdirs(relSymlinkRedhatRelease)
	require.NoError(t, os.Symlink("../release", relSymlinkRedhatRelease))
	write(filepath.Join(root, "rootfs-rhcos-rel-symlink/release"), "Hello")

	return root
}
