package wellknownnamespaces

import "strings"

// IsRHELNamespace returns true if the given argument identifies a RHEL namespace.
// The namespace is expected to be of form `namespacename:version`.
// For example: rhel:7, rhel:8, centos:8, ubuntu:14.04.
func IsRHELNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, "rhel")
}
