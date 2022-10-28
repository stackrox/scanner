package istioUtil

import (
	"github.com/hashicorp/go-version"
	"github.com/stackrox/istio-cves/types"
)

// IstioIsAffected gets the fixed-by version for vStr in Istion vuln.
func IstioIsAffected(vStr string, vuln types.Vuln) (bool, string, error) {
	v, err := version.NewVersion(vStr)
	if err != nil {
		return false, "", err
	}

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
