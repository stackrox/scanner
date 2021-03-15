package rhelv2

import (
	"compress/bzip2"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// fetch fetches the resource as specified by Fetcher.URL and
// Fetcher.Compression, using the client provided as Fetcher.Client.
//
// fetch makes GET requests, and will make conditional requests using the
// passed-in hint.
func fetch(url *url.URL) (io.ReadCloser, error) {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       url.Host,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		// break
	default:
		return nil, fmt.Errorf("rhelv2: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}

	return newReadCloser(res.Body), nil
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
