package nvdtoolscache

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/nvdloader"
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

func cpeIsApplication(cpe string) bool {
	spl := strings.SplitN(cpe, ":", 4)
	if len(spl) < 4 {
		return false
	}
	return spl[2] == "a"
}

func isNodeValid(node *schema.NVDCVEFeedJSON10DefNode) bool {
	if len(node.CPEMatch) != 0 {
		filteredCPEs := node.CPEMatch[:0]
		for _, cpe := range node.CPEMatch {
			if cpeIsApplication(cpe.Cpe23Uri) {
				filteredCPEs = append(filteredCPEs, cpe)
			}
		}
		node.CPEMatch = filteredCPEs
		return len(filteredCPEs) != 0
	}
	// Otherwise look at the children and make sure if the Operator is an AND they are all valid
	if strings.EqualFold(node.Operator, "and") {
		for _, c := range node.Children {
			if !isNodeValid(c) {
				return false
			}
		}
		return true
	}
	// Operator is an OR so ensure at least one is valid
	filteredNodes := node.Children[:0]
	for _, c := range node.Children {
		if isNodeValid(c) {
			filteredNodes = append(filteredNodes, c)
		}
	}
	node.Children = filteredNodes
	return len(filteredNodes) != 0
}

func isValidCVE(cve *schema.NVDCVEFeedJSON10DefCVEItem) bool {
	if cve.Configurations == nil {
		return false
	}
	filteredNodes := cve.Configurations.Nodes[:0]
	for _, n := range cve.Configurations.Nodes {
		if isNodeValid(n) {
			filteredNodes = append(filteredNodes, n)
		}
	}
	cve.Configurations.Nodes = filteredNodes
	return len(filteredNodes) != 0
}

func trimCVE(cve *schema.NVDCVEFeedJSON10DefCVEItem) {
	cve.CVE.References = nil
	cve.CVE.Affects = nil
	cve.CVE.DataType = ""
	cve.CVE.Problemtype = nil
	cve.CVE.DataVersion = ""
	cve.CVE.DataFormat = ""
	cve.Configurations.CVEDataVersion = ""
}

func (c *cacheImpl) handleJSONFile(path string) (int, error) {
	fmt.Println("Handling", path)
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
		if !isValidCVE(cve) {
			continue
		}

		vuln := nvd.ToVuln(cve)
		trimCVE(cve)

		err := c.addProductToCVE(vuln, cve)
		if err != nil {
			return 0, errors.Wrapf(err, "adding vuln %q", vuln.ID())
		}
		numVulns++
	}
	return numVulns, nil
}
