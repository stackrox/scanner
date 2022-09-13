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

	// rt stands for runtime and is in Java generally
	// docker and mesos are explicitly blocklisted as the packages don't have any keywords
	// and typically standalone
	blocklistedPkgs = []string{"rt", "docker", "mesos"}

	ignoredPkgs = []string{
		"jdbc",
	}

	mutableIndicators = []string{
		"all",
		"core",
		"fatjar",
		"scala-library",
		"common",
	}

	immutableIndicators = []string{
		"agent",
	}

	knownSpringVendors = []string{"pivotal", "pivotal_software", "vmware"}
	knownSpringComponents = set.NewFrozenStringSet(
		"spring_advanced_message_queuing_protocol",
		"spring_aop",
		"spring_beans",
		"spring_boot",
		"spring_boot_autoconfigure",
		"spring_boot_jarmode_layertools",
		"spring_cloud_function",
		"spring_cloud_function_core",
		"spring_cloud_gateway",
		"spring_cloud_netflix",
		"spring_cloud_openfeign",
		"spring_context",
		"spring_core",
		"spring_data_mongodb",
		"spring_data_rest",
		"spring_expression",
		"spring_jcl",
		"spring_security",
		"spring_security_core",
		"spring_security_crypto",
		"spring_security_oath",
		"spring_security_web",
		"spring_web",
		"spring_web_flow",
		"spring_webflux",
		"spring_webmvc",
	)
)

func isMutableName(name string) bool {
	for _, keyword := range immutableIndicators {
		if strings.Contains(name, keyword) {
			return false
		}
	}
	for _, keyword := range mutableIndicators {
		if strings.Contains(name, "-"+keyword) || strings.Contains(name, keyword+"-") {
			return true
		}
	}
	return false
}

func ignored(c *component.Component) bool {
	for _, ignore := range ignoredPkgs {
		// Not ignored: postgresql-jdbc
		// Ignored: postgresql with jdbc in manifest
		if strings.Contains(c.Name, ignore) {
			continue
		}
		if strings.Contains(strings.ToLower(c.JavaPkgMetadata.BundleName), ignore) {
			log.Debugf("Java: ignored %q based on bundle name: %v", c.Name, c.JavaPkgMetadata.BundleName)
			return true
		}
		if strings.Contains(filepath.Base(c.Location), ignore) {
			log.Debugf("Java: ignored %q based on location: %v", c.Name, c.Location)
			return true
		}
	}
	return false
}

func getPossibleVendors(origins []string, names set.StringSet) set.StringSet {
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
	// A lot of java pkgs have the vendor as apache so instead of having an empty with a lot of false positives
	// just add apache in hopes of catching some edge cases
	if vendorSet.Cardinality() == 0 {
		vendorSet.Add("apache")
	}

	// Add Spring-specific vendors.
	for name := range names {
		if knownSpringComponents.Contains(name) {
			vendorSet.AddAll(knownSpringVendors...)
			break
		}
	}

	return vendorSet
}

// GetJavaAttributes returns the Java-related attributes of the given component.
func GetJavaAttributes(c *component.Component) []*wfn.Attributes {
	java := c.JavaPkgMetadata
	if java == nil {
		return nil
	}
	if ignored(c) {
		return nil
	}
	// Purposefully ignore jboss unless it's exactly jboss.
	// JBoss is very difficult to handle as there are lots of flavors of its subpackage
	// and there isn't an easy way to sort through the data so error on the side of false negatives
	if c.Name != "jboss" && strings.Contains(c.Name, "jboss") {
		return nil
	}

	nameSet := common.GenerateNameKeys(c)
	vendorSet := getPossibleVendors(java.Origins, nameSet)
	versionSet := common.GenerateVersionKeys(c)
	for k := range versionSet {
		versionSet.Add(extensionRegex.ReplaceAllString(k, ""))
	}

	// Post filtering
	if isMutableName(c.Name) {
		common.AddMutatedNameKeys(c, nameSet)
	}
	for _, blocklisted := range blocklistedPkgs {
		nameSet.Remove(blocklisted)
	}

	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}
