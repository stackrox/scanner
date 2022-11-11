package istioutil

import (
	"github.com/hashicorp/go-version"
	"github.com/stackrox/istio-cves/types"
)

// IsAffected gets the fixed-by version for vStr in Istion vuln.
func IsAffected(v *version.Version, vuln types.Vuln) (bool, string, error) {
	for _, affected := range vuln.Affected {
		constraint, err := version.NewConstraint(affected.Range)
		if err != nil {
			return false, "", err
		}
		if constraint.Check(v) {
			return true, affected.FixedBy, nil
		}
	}

	return false, "", nil
}
