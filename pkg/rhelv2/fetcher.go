package rhelv2

import (
	"compress/bzip2"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// fetch fetches the resource as specified by the given URL,
// using the client provided in this package.
func fetch(url *url.URL) (string, io.ReadCloser, error) {
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
		return "", nil, err
	}
	if res.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("rhelv2: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}

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
