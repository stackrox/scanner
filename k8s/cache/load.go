package cache

import (
	"archive/zip"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
	"github.com/stackrox/scanner/pkg/ziputil"
)

// These are the names of Kubernetes components we detect on
const (
	KubeAPIServer         = "kube-apiserver"
	KubeAggregator        = "kube-aggregator"
	KubeControllerManager = "kube-controller-manager"
	KubeProxy             = "kube-proxy"
	KubeScheduler         = "kube-scheduler"
	Kubectl               = "kubectl"
	Kubelet               = "kubelet"
	// Generic includes the vulnerabilities not assigned to specific component(s).
	Generic = "__generic"
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

	log.Infof("Total vulns in %q: %d", definitionsDir, totalVulns)

	return nil
}

func (c *cacheImpl) LoadFromZip(zipR *zip.ReadCloser, definitionsDir string) error {
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

	log.Infof("Total vulns in %s: %d", definitionsDir, totalVulns)

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

	cveData, err := k8sloader.LoadYAMLFileFromReader(r)
	if err != nil {
		return false, errors.Wrapf(err, "loading YAML file at path %q", r.Name)
	}

	// No need to bother validating more than the following, as it is done on the data source's side.
	if cveData.CVE == "" {
		return false, nil
	}

	c.cacheRWLock.Lock()
	defer c.cacheRWLock.Unlock()
	if len(cveData.Components) == 0 {
		if c.cache[Generic] == nil {
			c.cache[Generic] = make(map[string]*validation.CVESchema)
		}
		c.cache[Generic][cveData.CVE] = cveData
	} else {
		for _, k8sComponent := range cveData.Components {
			if c.cache[k8sComponent] == nil {
				c.cache[k8sComponent] = make(map[string]*validation.CVESchema)
			}
			c.cache[k8sComponent][cveData.CVE] = cveData
		}
	}

	return true, nil
}
