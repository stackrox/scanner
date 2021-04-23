package cache

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
)

// These are the names of Kubernetes components we detect on
const (
	KubeProxy             = "kube-proxy"
	Kubectl               = "kubectl"
	Kubelet               = "kubelet"
	KubeAggregator        = "kube-aggregator"
	KubeAPIServer         = "kube-apiserver"
	KubeControllerManager = "kube-controller-manager"
	KubeScheduler         = "kube-scheduler"
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

	// No need to bother validating more than the following, as it is done on the data source's side.
	if cveData.CVE == "" {
		return false, nil
	}

	c.cacheRWLock.Lock()
	defer c.cacheRWLock.Unlock()
	if len(cveData.Components) == 0 {
		c.unsetVulns = append(c.unsetVulns, cveData)
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
