// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tarutil

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stretchr/testify/assert"
)

var testTarballs = []string{
	"utils_test.tar",
	"utils_test.tar.gz",
	"utils_test.tar.bz2",
	"utils_test.tar.xz",
}

func testfilepath(filename string) string {
	_, path, _, _ := runtime.Caller(0)
	testDataDir := "/testdata"
	return filepath.Join(filepath.Dir(path), testDataDir, filename)
}

func TestExtract(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.NoError(t, err)
		defer f.Close()

		data, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test/"))
		assert.NoError(t, err)

		if c, n := data.Get("test/test.txt"); !n {
			assert.Fail(t, "test/test.txt should have been extracted")
		} else {
			assert.NotEqual(t, 0, len(c.Contents) > 0, "test/test.txt file is empty")
		}
		if _, n := data.Get("test.txt"); n {
			assert.Fail(t, "test.txt should not be extracted")
		}
	}
}

func TestExtractUncompressedData(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.NoError(t, err)
		defer f.Close()

		_, err = ExtractFiles(bytes.NewReader([]byte("that string does not represent a tar or tar-gzip file")), matcher.NewPrefixAllowlistMatcher())
		assert.Error(t, err, "Extracting uncompressed data should return an error")
	}
}

func TestMaxExtractableFileSize(t *testing.T) {
	f, err := os.Open(testfilepath("utils_test.tar.gz"))
	assert.NoError(t, err)
	defer utils.IgnoreError(f.Close)
	files, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test_big.txt"))
	assert.NoError(t, err)
	// test_big.txt is of size 57 bytes.
	assert.Contains(t, files.data, "test_big.txt")

	SetMaxExtractableFileSize(50)
	files, err = ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test_big.txt"))
	assert.NoError(t, err)
	assert.Empty(t, files.data)
}

func TestExtractWithSymlink(t *testing.T) {
	f, err := os.Open(testfilepath("symlink.tar.gz"))
	assert.NoError(t, err)
	defer utils.IgnoreError(f.Close)
	expected := map[string]string{
		// Link to directory
		"dirlink":     "dir",
		"opt/dirlink": "dir",
		// Link to files
		"opt/symlink":     "dir/dir_file",
		"dir/symlink":     "dir/dir_file",
		"1/2/3/4/symlink": "dir/dir_file",
		// Multiple level symlinks
		"link/symlink": "dir/dir_file",
		// This is a loop of symlinks
		"link/link1": "link/link2",
		"link/link2": "link/link1",
		"l1":         "1",
		"1/l2":       "1/2",
		"1/2/l3":     "1/2/3",
		"1/2/3/l4":   "1/2/3/4",
		"l4":         "1/2/3/4",
		"lib64":      "1",
	}

	files, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher(""))
	base := LayerFiles{data: make(map[string]analyzer.FileData), links: map[string]string{"lib64": "l1"}}
	files.MergeBaseAndResolveSymlinks(&base)
	assert.NoError(t, err)
	assert.Len(t, files.data, 9)
	assert.Len(t, files.links, 16)

	for fileName, linkTo := range files.links {
		if target, ok := expected[fileName]; ok {
			assert.Equal(t, target, linkTo)
		}
	}
	verifyContent(t, files, "opt/dirlink/symlink")
	verifyContent(t, files, "l1/l2/l3/l4/symlink")
	verifyContent(t, files, "l1/2/l3/4/symlink")
	verifyContent(t, files, "opt/dirlink/dir_file")

	verifyContent(t, files, "lib64/2/l3/4/symlink")
}

func verifyContent(t *testing.T, files LayerFiles, p string) {
	fileData, exists := files.Get(p)
	assert.True(t, exists)
	assert.Equal(t, "test\n", string(fileData.Contents))
}
