package nvdtoolscache

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
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
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		numVulns, err := c.handleJSONFile(filepath.Join(definitionsDir, f.Name()))
		if err != nil {
			return errors.Wrapf(err, "handling file %s", f.Name())
		}
		totalVulns += numVulns
	}
	log.Infof("Total vulns in %q: %d", definitionsDir, totalVulns)

	utils.Must(c.sync())
	return nil
}

func (c *cacheImpl) LoadFromZip(zipR *zip.ReadCloser, definitionsDir string) error {
	log.WithField("dir", definitionsDir).Info("Loading definitions directory")

	readers, err := ziputil.OpenFilesInDir(zipR, definitionsDir, ".json")
	if err != nil {
		return err
	}

	var totalVulns int
	for _, r := range readers {
		numVulns, err := c.handleReader(r)
		if err != nil {
			return errors.Wrapf(err, "handling file %s", r.Name)
		}
		totalVulns += numVulns
	}
	log.Infof("Total vulns in %s: %d", definitionsDir, totalVulns)

	utils.Must(c.sync())
	return nil
}

func (c *cacheImpl) handleJSONFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrapf(err, "opening file at %q", path)
	}

	return c.handleReader(&ziputil.ReadCloser{
		ReadCloser: f,
		Name:       path,
	})
}

// handleReader loads the given reader and closes it when finished.
func (c *cacheImpl) handleReader(r *ziputil.ReadCloser) (int, error) {
	defer utils.IgnoreError(r.Close)

	feed, err := nvdloader.LoadJSONFileFromReader(r)
	if err != nil {
		return 0, errors.Wrapf(err, "loading JSON file at path %q", r.Name)
	}

	var numVulns int
	for _, cve := range feed.CVEItems {
		if cve == nil || cve.Configurations == nil {
			continue
		}

		vuln := nvd.ToVuln(cve)
		err := c.addProductToCVE(vuln, cve)
		if err != nil {
			return 0, errors.Wrapf(err, "adding vuln %q from %q", vuln.ID(), r.Name)
		}

		numVulns++
	}
	return numVulns, nil
}
