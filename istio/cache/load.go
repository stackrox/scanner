package cache

import (
	"archive/zip"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/istioloader"
	"github.com/stackrox/scanner/pkg/ziputil"
)

func (c *cacheImpl) LoadFromDirectory(definitionsDir string) error {
	log.WithField("dir", definitionsDir).Info("Loading definitions directory")

	files, err := os.ReadDir(definitionsDir)
	if err != nil {
		return err
	}

	var totalVulns int
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".yaml" {
			continue
		}
		updated, err := c.handleYAMLFile(filepath.Join(definitionsDir, f.Name()))
		if err != nil {
			log.Errorf("Skipping vuln update for %s due to error: %v", f.Name(), err)
			continue
		}
		if updated {
			totalVulns++
		}
	}

	log.Infof("Total updated vulns in %q: %d", definitionsDir, totalVulns)

	return nil
}

func (c *cacheImpl) LoadFromZip(zipR *zip.Reader, definitionsDir string) error {
	log.WithField("dir", definitionsDir).Info("Loading definitions directory")

	rs, err := ziputil.OpenFilesInDir(zipR, definitionsDir, ".yaml")
	if err != nil {
		return err
	}

	var totalVulns int
	for _, r := range rs {
		updated, err := c.handleReader(r)
		if err != nil {
			return errors.Wrapf(err, "handling file %s", r.Name)
		}
		if updated {
			totalVulns++
		}
	}

	log.Infof("Total vuln files in %s: %d", definitionsDir, totalVulns)

	return nil
}

func (c *cacheImpl) handleYAMLFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, errors.Wrapf(err, "opening file at %q", path)
	}

	return c.handleReader(&ziputil.ReadCloser{
		ReadCloser: f,
		Name:       path,
	})
}

// handleReader loads the data from the given reader and closes the reader once done.
func (c *cacheImpl) handleReader(r *ziputil.ReadCloser) (bool, error) {
	defer utils.IgnoreError(r.Close)

	cveData, err := istioloader.LoadYAMLFileFromReader(r)
	if err != nil {
		return false, errors.Wrapf(err, "loading YAML file at path %q", r.Name)
	}

	c.cacheRWLock.Lock()
	defer c.cacheRWLock.Unlock()

	name := cveData.Name
	c.cache[name] = cveData

	return true, nil
}
