package golangutils

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	modBaseNameRegex = regexp.MustCompile(`^.*/([^/]+(?:/v\d+)?)$`)
)

// ParseModuleName splits a full module name into a base name and vendor portion. For example,
// helm.sh/helm/v3 is split into the name "helm/v3", and the vendor "helm.sh".
func ParseModuleName(modName string) (baseName string, vendor string, err error) {
	modBaseNameMatches := modBaseNameRegex.FindStringSubmatch(modName)
	if len(modBaseNameMatches) != 2 {
		return "", "", errors.Errorf("invalid module name %q", modName)
	}

	baseName = modBaseNameMatches[1]
	vendor = strings.TrimSuffix(modName, "/"+baseName)
	return baseName, vendor, nil
}
