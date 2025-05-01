package rhelv2

import (
	"compress/bzip2"
	"io"
	"net/http"
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/retry"
)

var (
	errEmptyOVAL = errors.New("OVAL file is empty")
)

// fetch fetches the resource as specified by the given URL,
// using the client provided in this package.
func fetch(uri string) (string, io.ReadCloser, error) {
	var (
		lastModified string
		body         io.ReadCloser
	)
	tries := 5
	err := retry.WithRetry(func() error {
		var err error
		lastModified, body, err = doFetch(uri)
		return err
	}, retry.BetweenAttempts(func(previousAttemptNumber int) {
		log.Warnf("Attempt %d/%d to GET %s failed...", previousAttemptNumber, tries, uri)
	}), retry.OnlyRetryableErrors(), retry.Tries(tries))
	return lastModified, body, err
}

// doFetch performs the actual fetching.
func doFetch(uri string) (string, io.ReadCloser, error) {
	// No context needed as the client has a timeout.
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return "", nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", nil, retry.MakeRetryable(err)
	}

	bodyToClose := res.Body
	defer func() {
		if bodyToClose != nil {
			_ = bodyToClose.Close()
		}
	}()

	if res.StatusCode != http.StatusOK {
		return "", nil, retry.MakeRetryable(errors.Errorf("rhelv2: fetcher got unexpected HTTP response for %s: %d (%s)", uri, res.StatusCode, res.Status))
	}

	if contentLength := res.Header.Get("content-length"); contentLength != "" {
		length, err := strconv.Atoi(contentLength)
		if err == nil && length == 0 {
			log.Warnf("Empty OVAL file: %s", uri)
			return "", nil, errEmptyOVAL
		}
	}

	bodyToClose = nil
	return res.Header.Get("last-modified"), newReadCloser(res.Body), nil
}

type readCloser struct {
	io.Reader
	body io.ReadCloser
}

func newReadCloser(body io.ReadCloser) io.ReadCloser {
	return &readCloser{
		Reader: bzip2.NewReader(body),
		body:   body,
	}
}

func (rc *readCloser) Close() error {
	return rc.body.Close()
}
