package rhelv2

import (
	"compress/bzip2"
	"context"
	"fmt"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stackrox/scanner/database"
)

// PulpManifest is the url for the Red Hat OVAL pulp repository.
const PulpManifest = `https://www.redhat.com/security/data/oval/v2/PULP_MANIFEST`

var (
	u, _ = url.Parse(PulpManifest)

	client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: proxy.RoundTripper(),
	}
)

func UpdateV2() ([]*database.RHELv2Vulnerability, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	switch res.StatusCode {
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("rhelv2: unexpected response: %v", res.Status)
	}

	m := Manifest{}
	if err := m.Load(res.Body); err != nil {
		return nil, err
	}

	var wg *sync.WaitGroup
	type response struct {
		vulns []*database.RHELv2Vulnerability
		err   error
	}
	respC := make(chan *response)
	errorList := errorhelpers.NewErrorList("rhelv2: updating feeds")

	for _, e := range m {
		name := strings.TrimSuffix(strings.Replace(e.Path, "/", "-", -1), ".oval.xml.bz2")
		uri, err := u.Parse(e.Path)
		if err != nil {
			return nil, err
		}
		p := uri.Path
		var release Release
		switch {
		case strings.Contains(p, "RHEL8"):
			release = RHEL8
		case strings.Contains(p, "RHEL7"):
			// We need to disregard this OVAL stream because some advisories therein have
			// been released with the CPEs identical to those used in classic RHEL stream.
			// This in turn causes false CVEs to appear in scanned images. Red Hat Product
			// Security is working on fixing this situation and the plan is to remove this
			// exception in the future.
			if name == "RHEL7-rhel-7-alt" {
				continue
			}
			release = RHEL7
		case strings.Contains(p, "RHEL6"):
			release = RHEL6
		default: // skip
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			u, _ := url.Parse(uri.String())
			r, err := fetch(context.Background(), u)
			if err != nil {
				respC <- &response{err:   err}
				return
			}

			vulns, err := parse(release, r)
			if err != nil {
				respC <- &response{err:   err}
				return
			}

			respC <- &response{vulns: vulns}
		}()
	}

	go func() {
		wg.Wait()
		close(respC)
	}()

	var vulns []*database.RHELv2Vulnerability
	for resp := range respC {
		if resp.err != nil {
			errorList.AddError(resp.err)
			continue
		}
		vulns = append(vulns, resp.vulns...)
	}

	return vulns, errorList.ToError()
}

// Fetch fetches the resource as specified by Fetcher.URL and
// Fetcher.Compression, using the client provided as Fetcher.Client.
//
// Fetch makes GET requests, and will make conditional requests using the
// passed-in hint.
//
// Tmp.File is used to return a ReadCloser that outlives the passed-in context.
func fetch(ctx context.Context, url *url.URL) (io.Reader, error) {
	req := http.Request{
		Method: http.MethodGet,
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
