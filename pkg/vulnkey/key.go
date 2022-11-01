package vulnkey

import "github.com/stackrox/scanner/database"

// Key represents a unique identified for a vulnerability to be used as a key.
type Key struct {
	name      string
	namespace string
}

// FromVuln creates a Key from the given *database.Vulnerability.
// It is expected the vulnerability is not nil and the namespace is not nil.
func FromVuln(v *database.Vulnerability) Key {
	return Key{
		name:      v.Name,
		namespace: v.Namespace.Name,
	}
}
