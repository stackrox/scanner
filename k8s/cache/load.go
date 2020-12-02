package cache

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/utils"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
)

var (
	strComponentToV1 = map[string]v1.KubernetesComponent_KubernetesComponent{
		"client-go":               v1.KubernetesComponent_CLIENT_GO,
		"kube-aggregator":         v1.KubernetesComponent_KUBE_AGGREGATOR,
		"kube-apiserver":          v1.KubernetesComponent_KUBE_APISERVER,
		"kube-controller-manager": v1.KubernetesComponent_KUBE_CONTROLLER_MANAGER,
		"kube-dns":                v1.KubernetesComponent_KUBE_DNS,
		"kube-proxy":              v1.KubernetesComponent_KUBE_PROXY,
		"kube-scheduler":          v1.KubernetesComponent_KUBE_SCHEDULER,
		"kubectl":                 v1.KubernetesComponent_KUBECTL,
		"kubelet":                 v1.KubernetesComponent_KUBELET,
	}
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

	// No need to bother validating more than the following, as it is done on the data source's side.
	if cveData.CVE == "" {
		return false, nil
	}

	k8sComponents := make([]v1.KubernetesComponent_KubernetesComponent, 0, len(cveData.Components))
	for _, component := range cveData.Components {
		k8sComponent, exists := strComponentToV1[component]
		if !exists {
			return false, errors.Errorf("Read invalid component (%s) while reading components in YAML file at path %q", component, path)
		}
		k8sComponents = append(k8sComponents, k8sComponent)
	}

	c.cacheRWLock.Lock()
	defer c.cacheRWLock.Unlock()
	if len(k8sComponents) == 0 {
		c.unsetVulns = append(c.unsetVulns, cveData)
	} else {
		for _, k8sComponent := range k8sComponents {
			if c.cache[k8sComponent] == nil {
				c.cache[k8sComponent] = make(map[string]*validation.CVESchema)
			}
			c.cache[k8sComponent][cveData.CVE] = cveData
		}
	}

	return true, nil
}
