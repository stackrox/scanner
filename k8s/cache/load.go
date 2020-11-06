package cache

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
)

func (c *cacheImpl) LoadFromDirectory(definitionsDir string) error {
	log.WithField("dir", definitionsDir).Info("Loading definitions directory")

	files, err := ioutil.ReadDir(definitionsDir)
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
			return errors.Wrapf(err, "handling file %s", f.Name())
		}
		if updated {
			totalVulns++
		}
	}

	log.Infof("Total vulns in %q: %d", definitionsDir, totalVulns)

	return nil
}

func (c *cacheImpl) handleYAMLFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, errors.Wrapf(err, "opening file at %q", path)
	}
	defer utils.IgnoreError(f.Close)

	cveData, err := k8sloader.LoadYAMLFileFromReader(f)
	if err != nil {
		return false, errors.Wrapf(err, "loading YAML file at path %q", path)
	}

	// No need to bother validating more than this, as it is done on the data source's side.
	if cveData.CVE == "" {
		return false, nil
	}

	c.cacheRWLock.Lock()
	defer c.cacheRWLock.Unlock()
	c.cache[cveData.CVE] = cveData

	return true, nil
}
