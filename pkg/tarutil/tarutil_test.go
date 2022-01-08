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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/rox/pkg/utils"
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
		assert.Nil(t, err)
		defer f.Close()

		data, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test/"))
		assert.Nil(t, err)

		if c, n := data["test/test.txt"]; !n {
			assert.Fail(t, "test/test.txt should have been extracted")
		} else {
			assert.NotEqual(t, 0, len(c.Contents) > 0, "test/test.txt file is empty")
		}
		if _, n := data["test.txt"]; n {
			assert.Fail(t, "test.txt should not be extracted")
		}
	}
}

func TestExtractUncompressedData(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.Nil(t, err)
		defer f.Close()

		_, err = ExtractFiles(bytes.NewReader([]byte("that string does not represent a tar or tar-gzip file")), matcher.NewPrefixAllowlistMatcher())
		assert.Error(t, err, "Extracting uncompressed data should return an error")
	}
}

func TestMaxExtractableFileSize(t *testing.T) {
	f, err := os.Open(testfilepath("utils_test.tar.gz"))
	assert.Nil(t, err)
	defer utils.IgnoreError(f.Close)
	contents, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test_big.txt"))
	assert.NoError(t, err)
	// test_big.txt is of size 57 bytes.
	assert.Contains(t, contents, "test_big.txt")

	SetMaxExtractableFileSize(50)
	contents, err = ExtractFiles(f, matcher.NewPrefixAllowlistMatcher("test_big.txt"))
	assert.NoError(t, err)
	assert.Empty(t, contents)
}

func TestExtractWithSymlink(t *testing.T) {
	f, err := os.Open(testfilepath("symlink.tar.gz"))
	assert.Nil(t, err)
	defer utils.IgnoreError(f.Close)
	expected := map[string]string{
		// Link to directory
		"dirlink":     "dir",
		"opt/dirlink": "dir",
		// Link to files
		"opt/symlink": "dir/dir_file",
		"dir/symlink": "dir/dir_file",
		// Multiple level symlinks
		"link/symlink": "dir/dir_file",
		// This is a loop of symlinks
		"link/link1": "link/link2",
		"link/link2": "link/link1",
		"l1": "1",
		"1/l2": "1/2",
		"1/2/l3": "1/2/3",
		"1/2/3/l4": "1/2/3/4",
		"l4": "1/2/3/4",
	}

	contents, err := ExtractFiles(f, matcher.NewPrefixAllowlistMatcher(""))
	assert.NoError(t, err)
	assert.Len(t, contents, 22)

	for fileName, fileData := range contents {
		fmt.Println(fileName)
		if target, ok := expected[fileName]; ok {
			assert.Equal(t, target, fileData.LinkTo)
		} else {
			assert.Equal(t, "", fileData.LinkTo)
		}
	}
	assert.Equal(t, "test\n", string(contents.Get("opt/dirlink/symlink").Contents))
	assert.Equal(t, "file\n", string(contents.Get("l1/l2/l3/l4/file").Contents))
}
