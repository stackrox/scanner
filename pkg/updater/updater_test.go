package updater

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/fileutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	url = "https://storage.googleapis.com/definitions.stackrox.io/e799c68a-671f-44db-9682-f24248cd0ffe/diff.zip"
)

var (
	nov23 = time.Date(2019, time.November, 23, 0, 0, 0, 0, time.Local)
)

func assertOnFileExistence(t *testing.T, path string, shouldExist bool) {
	exists, err := fileutils.Exists(path)
	require.NoError(t, err)
	require.Equal(t, shouldExist, exists)
}

func TestFetchDumpFromGoogleStorage(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}
	tempDir, err := ioutil.TempDir("", "go-fetch-dump-test")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tempDir))
	}()

	outputPath := filepath.Join(tempDir, "dump.zip")
	// Should not fetch since it can't be updated in a time in the future.
	updated, err := fetchDumpFromGoogleStorage(concurrency.Never(), client, url, time.Now().Add(time.Minute), outputPath)
	require.NoError(t, err)
	assert.False(t, updated)
	assertOnFileExistence(t, outputPath, false)

	// Should definitely fetch.
	updated, err = fetchDumpFromGoogleStorage(concurrency.Never(), client, url, nov23, outputPath)
	require.NoError(t, err)
	assert.True(t, updated)
	assertOnFileExistence(t, outputPath, true)
}
