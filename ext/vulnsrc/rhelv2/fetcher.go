package rhelv2

import (
	"compress/bzip2"
	"context"
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
func fetch(ctx context.Context, url *url.URL) (io.Reader, error) {
	req := http.Request{
		Method:     http.MethodGet,
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       url.Host,
	}

	res, err := client.Do(req.WithContext(ctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		// break
	default:
		return nil, fmt.Errorf("rhel2: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}

	return bzip2.NewReader(res.Body), nil
}
