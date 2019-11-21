package java

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	extensionRegex = regexp.MustCompile(`\.(RELEASE|GA|SEC.*)$`)

	blacklistedPkgs = []string{"rt", "docker", "mesos"}

	// predisposedKeywords are the keywords that are likely to be used to specify
	// a version of a product that is not the core product. jira-plugin should not be resolved as jira for example
	// postgres-client is not postgres
	predisposedKeywords = []string{
		"plugin",
		"client",
		"java",
		"integration",
		"jdbc",
		"annotations",
		"spec",
		"jsr181",
		"docker",
		"mesos",
	}

	ignoredPkgs = []string{
		"jdbc",
	}
)

func predisposed(c *component.Component) bool {
	for _, keyword := range predisposedKeywords {
		if strings.Contains(c.Name, keyword) {
			return true
		}
		if strings.Contains(c.Location, keyword) {
			return true
		}
	}
	return false
}

func ignored(c *component.Component) bool {
	for _, ignore := range ignoredPkgs {
		// Not ignored: postgresql-jdbc
		// Ignored: postgresql with jdbc in manifest
		if !strings.Contains(c.Name, ignore) {
			if strings.Contains(strings.ToLower(c.JavaPkgMetadata.BundleName), ignore) {
				log.Debugf("Java: ignored %q based on bundle name: %v", c.Name, c.JavaPkgMetadata.BundleName)
				return true
			}
			if strings.Contains(filepath.Base(c.Location), ignore) {
				log.Debugf("Java: ignored %q based on location: %v", c.Name, c.Location)
				return true
			}
		}
	}
	return false
}

func getPossibleVendors(origins []string) set.StringSet {
	// Try splitting on periods
	vendorSet := set.NewStringSet()
	for _, orig := range origins {
		for _, splOrig := range strings.Split(orig, ".") {
			if splOrig != "" {
				vendorSet.Add(splOrig)
			}
		}
		for _, splOrig := range strings.Split(orig, " ") {
			if splOrig != "" {
				vendorSet.Add(strings.ToLower(splOrig))
			}
		}
	}
	if vendorSet.Cardinality() == 0 {
		vendorSet.Add("apache")
	}
	return vendorSet
}

func GetJavaAttributes(c *component.Component) []*wfn.Attributes {
	java := c.JavaPkgMetadata
	if java == nil {
		return nil
	}
	if ignored(c) {
		return nil
	}
	// Purposefully ignore jboss unless it's exactly jboss
	if c.Name != "jboss" && strings.Contains(c.Name, "jboss") {
		return nil
	}

	vendorSet := getPossibleVendors(java.Origins)
	nameSet := common.GenerateNameKeys(c)
	versionSet := common.GenerateVersionKeys(c)
	for k := range versionSet {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	// Post filtering
	if vendorSet.Cardinality() != 0 && !predisposed(c) {
		common.AddMutatedNameKeys(c, nameSet)
	}
	for _, blacklisted := range blacklistedPkgs {
		nameSet.Remove(blacklisted)
	}

	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}
