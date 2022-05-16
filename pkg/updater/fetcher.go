package updater

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/httputil"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	ifModifiedSinceHeader = "If-Modified-Since"
	defaultTimeout        = 5 * time.Minute
)

func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
}

func fetchDumpFromURL(ctx concurrency.Waitable, client *http.Client, url string, lastUpdatedTime time.Time, outputPath string) (bool, error) {
	// First, head the URL to see when it was last modified.
	req, err := http.NewRequestWithContext(concurrency.AsContext(ctx), http.MethodGet, url, nil)
	if err != nil {
		return false, errors.Wrap(err, "constructing req")
	}
	req.Header.Set(ifModifiedSinceHeader, lastUpdatedTime.UTC().Format(http.TimeFormat))
	resp, err := client.Do(req)
	if err != nil {
		return false, errors.Wrap(err, "executing request")
	}
	defer utils.IgnoreError(resp.Body.Close)
	if resp.StatusCode == http.StatusNotModified {
		// Not modified
		return false, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		logrus.Warnf("definition not found: %s", url)
		return false, nil
	}
	if err := httputil.ResponseToError(resp); err != nil {
		return false, err
	}
	outFile, err := os.Create(outputPath)
	if err != nil {
		return false, errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outFile.Close)
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "streaming response to file")
	}
	return true, nil
}
