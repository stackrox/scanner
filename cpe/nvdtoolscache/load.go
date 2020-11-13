package nvdtoolscache

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
)

func (c *cacheImpl) LoadFromDirectory(definitionsDir string) error {
	log.WithField("dir", definitionsDir).Info("Loading definitions directory")

	files, err := ioutil.ReadDir(definitionsDir)
	if err != nil {
		return err
	}

	var totalVulns int
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		numVulns, err := c.handleJSONFile(filepath.Join(definitionsDir, f.Name()))
		if err != nil {
			return errors.Wrapf(err, "handling file %s", f.Name())
		}
		totalVulns += numVulns
	}
	log.Infof("Total vulns: %d", totalVulns)

	utils.Must(c.sync())
	return nil
}

func (c *cacheImpl) handleJSONFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrapf(err, "opening file at %q", path)
	}
	defer utils.IgnoreError(f.Close)

	feed, err := nvdloader.LoadJSONFileFromReader(f)
	if err != nil {
		return 0, errors.Wrapf(err, "loading JSON file at path %q", path)
	}

	var numVulns int
	for _, cve := range feed.CVEItems {
		if cve == nil || cve.Configurations == nil {
			continue
		}
		vuln := nvd.ToVuln(cve)

		err := c.addProductToCVE(vuln, cve)
		if err != nil {
			return 0, errors.Wrapf(err, "adding vuln %q", vuln.ID())
		}
		numVulns++
	}
	return numVulns, nil
}
