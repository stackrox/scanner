package rhelv2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/quay/claircore/rhel/pulp"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/vulndump"
	"go.uber.org/ratelimit"
)

const (
	// PulpManifest is the url for the Red Hat OVAL pulp repository.
	PulpManifest = `https://www.redhat.com/security/data/oval/v2/PULP_MANIFEST`

	// Repo2CPEMappingURL is the URL with a mapping file provided by Red Hat.
	Repo2CPEMappingURL = `https://www.redhat.com/security/data/metrics/repository-to-cpe.json`
)

var (
	u *url.URL

	client = &http.Client{
		Timeout:   20 * time.Second,
		Transport: proxy.RoundTripper(),
	}

	// Limits to 10 ops/second.
	// Red Hat OVAL v2 feed has a rate limit of ~12 requests/second.
	rl = ratelimit.New(10)

	redhatAdvisoryPrefixes = []string{
		"RHSA-",
		"RHBA-",
		"RHEA-",
	}
)

func init() {
	var err error
	u, err = url.Parse(PulpManifest)
	utils.Must(err)
}

// IsRedHatAdvisory returns if the passed vulnerability is a Red Hat advisory
func IsRedHatAdvisory(cve string) bool {
	for _, prefix := range redhatAdvisoryPrefixes {
		if strings.HasPrefix(cve, prefix) {
			return true
		}
	}
	return false
}

// UpdateV2 reads the RHEL OVAL v2 feeds and writes them into a known directory.
func UpdateV2(outputDir string) (int, error) {
	repoToCPE, err := updateRepoToCPE(outputDir)
	if err != nil {
		return 0, err
	}
	cpes := set.NewStringSet()
	for _, v := range repoToCPE.Data {
		cpes.AddAll(v.CPEs...)
	}

	// No context needed as the client has a 20 second timeout.
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}

	rl.Take()
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer utils.IgnoreError(res.Body.Close)

	if res.StatusCode != http.StatusOK {
		return 0, errors.Errorf("rhelv2: unexpected response getting manifest: %v", res.Status)
	}

	// Declare this way to prevent warnings.
	m := pulp.Manifest{}
	if err := m.Load(res.Body); err != nil {
		return 0, err
	}

	rhelV2Dir := filepath.Join(outputDir, vulndump.RHELv2DirName, vulndump.RHELv2VulnsSubDirName)
	if err := os.MkdirAll(rhelV2Dir, 0755); err != nil {
		return 0, errors.Wrapf(err, "creating subdir for %s", vulndump.RHELv2VulnsSubDirName)
	}

	var wg sync.WaitGroup
	type response struct {
		vulns int
		err   error
	}
	respC := make(chan *response)
	errorList := errorhelpers.NewErrorList("rhelv2: updating feeds")

	for _, e := range m {
		///////////////////////////////////////////////////
		// BEGIN
		// Influenced by ClairCore under Apache 2.0 License
		// https://github.com/quay/claircore
		///////////////////////////////////////////////////
		name := strings.TrimSuffix(strings.Replace(e.Path, "/", "-", -1), ".oval.xml.bz2")
		uri, err := u.Parse(e.Path)
		if err != nil {
			return 0, err
		}
		p := uri.Path
		switch {
		case strings.Contains(p, "RHEL6") || strings.Contains(p, "RHEL8"):
		case strings.Contains(p, "RHEL7"):
			// We need to disregard this OVAL stream because some advisories therein have
			// been released with the CPEs identical to those used in classic RHEL stream.
			// This in turn causes false CVEs to appear in scanned images. Red Hat Product
			// Security is working on fixing this situation and the plan is to remove this
			// exception in the future.
			if name == "RHEL7-rhel-7-alt" {
				continue
			}
		default: // skip
			continue
		}
		///////////////////////////////////////////////////
		// END
		// Influenced by ClairCore under Apache 2.0 License
		// https://github.com/quay/claircore
		///////////////////////////////////////////////////

		wg.Add(1)
		go func() {
			defer wg.Done()

			rl.Take()
			lastModifiedStr, r, err := fetch(uri.String())
			if err != nil {
				if err != errEmptyOVAL {
					respC <- &response{err: err}
				}
				return
			}
			defer utils.IgnoreError(r.Close)

			lastModified, err := time.Parse(time.RFC1123, lastModifiedStr)
			if err != nil {
				respC <- &response{err: err}
			}

			vulns, err := parse(cpes, uri.String(), r)
			if err != nil {
				respC <- &response{err: err}
				return
			}

			outF, err := os.Create(filepath.Join(rhelV2Dir, fmt.Sprintf("%s.json", name)))
			if err != nil {
				respC <- &response{err: errors.Wrapf(err, "failed to create file %s", name)}
				return
			}
			defer utils.IgnoreError(outF.Close)

			if err := json.NewEncoder(outF).Encode(&vulndump.RHELv2{
				LastModified: lastModified,
				Vulns:        vulns,
			}); err != nil {
				respC <- &response{err: errors.Wrapf(err, "JSON-encoding %s", name)}
				return
			}

			respC <- &response{vulns: len(vulns)}
		}()
	}

	go func() {
		wg.Wait()
		close(respC)
	}()

	var nRHELv2Vulns int
	for resp := range respC {
		if resp.err != nil {
			errorList.AddError(resp.err)
			continue
		}
		nRHELv2Vulns += resp.vulns
	}

	return nRHELv2Vulns, errorList.ToError()
}

func updateRepoToCPE(outputDir string) (*repo2cpe.RHELv2MappingFile, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, Repo2CPEMappingURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if resp != nil {
		defer utils.IgnoreError(resp.Body.Close)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("received status code %q querying mapping url", resp.StatusCode)
	}

	// We could just copy the contents over, but this acts a sanity check to ensure it is in the form we expect.
	var mapping repo2cpe.RHELv2MappingFile
	err = json.NewDecoder(resp.Body).Decode(&mapping)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode mapping file")
	}

	rhelV2Dir := filepath.Join(outputDir, vulndump.RHELv2DirName)
	if err := os.MkdirAll(rhelV2Dir, 0755); err != nil {
		return nil, errors.Wrapf(err, "creating subdir for %s", vulndump.RHELv2DirName)
	}

	outF, err := os.Create(filepath.Join(rhelV2Dir, repo2cpe.RHELv2CPERepoName))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create file %s", repo2cpe.RHELv2CPERepoName)
	}
	defer utils.IgnoreError(outF.Close)

	return &mapping, json.NewEncoder(outF).Encode(&mapping)
}
