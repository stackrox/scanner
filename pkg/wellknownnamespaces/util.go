package wellknownnamespaces

import "strings"

func IsRHELNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, "rhel")
}
