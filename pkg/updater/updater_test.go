package updater

import (
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	url = "https://storage.googleapis.com/definitions.stackrox.io/e799c68a-671f-44db-9682-f24248cd0ffe/diff.zip"
)

var (
	nov23 = time.Date(2019, time.November, 23, 0, 0, 0, 0, time.Local)
)

func TestFetchDumpFromGoogleStorage(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}
	tempDir, err := ioutil.TempDir("", "go-fetch-dump-test")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tempDir))
	}()

	sig := concurrency.NewSignal()
	updater := &Updater{
		lastUpdatedTime:    time.Now().Add(time.Minute),
		client:             client,
		interval:           0,
		downloadURL:        url,
		fetchIsFromCentral: false,
		stopSig:            &sig,
	}

	// Should not fetch since it can't be updated in a time in the future.
	closer, err := updater.fetchDumpFromURL()
	require.NoError(t, err)
	assert.Nil(t, closer)

	updater.lastUpdatedTime = nov23
	// Should definitely fetch.
	closer, err = updater.fetchDumpFromURL()
	require.NoError(t, err)
	assert.NotNil(t, closer)
}
