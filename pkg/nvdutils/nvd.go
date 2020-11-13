package nvdutils

import (
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

func cpeIsApplication(cpe string) bool {
	spl := strings.SplitN(cpe, ":", 4)
	if len(spl) < 4 {
		return false
	}
	return spl[2] == "a"
}

func isNodeValid(node *schema.NVDCVEFeedJSON10DefNode) bool {
	if len(node.CPEMatch) != 0 {
		filteredCPEs := node.CPEMatch[:0]
		for _, cpe := range node.CPEMatch {
			if cpeIsApplication(cpe.Cpe23Uri) {
				filteredCPEs = append(filteredCPEs, cpe)
			}
		}
		node.CPEMatch = filteredCPEs
		return len(filteredCPEs) != 0
	}
	// Otherwise look at the children and make sure if the Operator is an AND they are all valid
	if strings.EqualFold(node.Operator, "and") {
		for _, c := range node.Children {
			if !isNodeValid(c) {
				return false
			}
		}
		return true
	}
	// Operator is an OR so ensure at least one is valid
	filteredNodes := node.Children[:0]
	for _, c := range node.Children {
		if isNodeValid(c) {
			filteredNodes = append(filteredNodes, c)
		}
	}
	node.Children = filteredNodes
	return len(filteredNodes) != 0
}

// CheckValidityAndTrim prunes the nodes of a CVE to only CPEs with applications
// and trims the unnecessary data
func CheckValidityAndTrim(cve *schema.NVDCVEFeedJSON10DefCVEItem) bool {
	if cve.Configurations == nil {
		return false
	}
	filteredNodes := cve.Configurations.Nodes[:0]
	for _, n := range cve.Configurations.Nodes {
		if isNodeValid(n) {
			filteredNodes = append(filteredNodes, n)
		}
	}
	cve.Configurations.Nodes = filteredNodes
	trimCVE(cve)
	return len(filteredNodes) != 0
}

// trimCVE removes data from the schema that we do not need for reduced memory pressure and
// file size
func trimCVE(cve *schema.NVDCVEFeedJSON10DefCVEItem) {
	cve.CVE.References = nil
	cve.CVE.Affects = nil
	cve.CVE.DataType = ""
	cve.CVE.Problemtype = nil
	cve.CVE.DataVersion = ""
	cve.CVE.DataFormat = ""
	cve.Configurations.CVEDataVersion = ""
}
