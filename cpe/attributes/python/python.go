package python

import (
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/attributes/common"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	blacklistedPkgs = []string{"python", "docker"}

	// predisposedKeywords are the keywords that are likely to be used to specify
	// a version of a product that is not the core product. jira-plugin should not be resolved as jira for example
	// postgres-client is not postgres
	predisposedKeywords = []string{
		"plugin",
		"client",
		"python",
		"integration",
	}

	summaryExcludedKeywords = []string{
		"client",
		"plugin",
	}
)

func predisposed(c *component.Component) bool {
	for _, keyword := range predisposedKeywords {
		if strings.Contains(c.Name, keyword) {
			return true
		}
	}
	return false
}

func ignored(c *component.Component) bool {
	for _, excluded := range summaryExcludedKeywords {
		// Ignore all clients, plugins, etc if they don't have the substring python so
		// we should capture things like python-dns or pydns and then these will be predisposed and not split
		// py is more prone to false positives as normal words have py, but it's proven to be fairly effective
		if !strings.Contains(c.Name, excluded) && !strings.Contains(c.Name, "py") {
			if strings.Contains(strings.ToLower(c.PythonPkgMetadata.Description), excluded) {
				log.Debugf("Python pkg ignored: %q - description %q contained %q", c.Name, c.PythonPkgMetadata.Description, excluded)
				return true
			}
			if strings.Contains(strings.ToLower(c.PythonPkgMetadata.Summary), excluded) {
				log.Debugf("Python pkg ignored: %q - summary %q contained %q", c.Name, c.PythonPkgMetadata.Summary, excluded)
				return true
			}
		}
	}
	return false
}

func GetPythonAttributes(c *component.Component) []*wfn.Attributes {
	python := c.PythonPkgMetadata
	if python == nil {
		return nil
	}
	if ignored(c) {
		return nil
	}

	vendorSet := set.NewStringSet()
	versionSet := common.GenerateVersionKeys(c)
	nameSet := common.GenerateNameKeys(c)

	// Post filtering
	if vendorSet.Cardinality() != 0 && !predisposed(c) {
		common.AddMutatedNameKeys(c, nameSet)
	}
	for _, blacklisted := range blacklistedPkgs {
		nameSet.Remove(blacklisted)
	}

	if python.Homepage != "" {
		url := strings.TrimPrefix(python.Homepage, "http://")
		url = strings.TrimPrefix(url, "https://")
		url = strings.TrimPrefix(url, "www.")
		if idx := strings.Index(url, "."); idx != -1 {
			vendorSet.Add(url[:idx])
		}
	}
	if python.AuthorEmail != "" {
		startIdx := strings.Index(python.AuthorEmail, "@")
		if startIdx != -1 && startIdx != len(python.AuthorEmail)-1 {
			endIdx := strings.Index(python.AuthorEmail[startIdx+1:], ".")
			vendorSet.Add(python.AuthorEmail[startIdx+1 : startIdx+endIdx+1])
		}
	}
	if strings.HasPrefix(python.DownloadURL, "https://pypi.org/project/") {
		project := strings.TrimPrefix(python.DownloadURL, "https://pypi.org/project/")
		project = strings.TrimSuffix(project, "/")
		vendorSet.Add(strings.ToLower(fmt.Sprintf("%s_project", project)))
	}
	vendorSet.Add("python")
	// purposefully add an empty vendor. This will be evaluated in the python validator
	vendorSet.Add("")
	return common.GenerateAttributesFromSets(vendorSet, nameSet, versionSet, "")
}
