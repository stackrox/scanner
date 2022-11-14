package istioutil

import (
	"github.com/hashicorp/go-version"
	"github.com/stackrox/istio-cves/types"
)

// IsAffected returns whether the given version of Istio is affected by the given vulnerability.
// If it is, then the fixed-by version is returned as well.
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
