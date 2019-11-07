package common

import (
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/component"
)

// HasNameAndVersion is a utility function that returns whether
// the passed component has a name and version.
// It is safe to pass a nil-component; this function will return false.
func HasNameAndVersion(c *component.Component) bool {
	return c != nil && stringutils.AllNotEmpty(c.Name, c.Version)
}
