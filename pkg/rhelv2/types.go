package rhelv2

import "fmt"

type SecurityDataCVE struct {
	ThreatSeverity string `json:"threat_severity"`
	PackageState []SecurityDataPackageState `json:"package_state"`
}

// ['Affected','Fix deferred','New','Not affected','Will not fix', 'Out of support scope'].

type SecurityDataPackageState struct {
	Product  string `json:"product_name"`
	Package  string `json:"package_name"`
	CPE      string `json:"cpe"`
	FixState string `json:"fix_state"`
}

func (s *SecurityDataPackageState) String() string {
	return fmt.Sprintf("%s %s %s %s", s.Product, s.Package, s.CPE, s.FixState)
}
