package ghsa

// GroupByAdvisory takes in a list of vulnerability connections, and returns a map mapping
// an advisory ID to the advisory metadata, along with all extracted vulnerabilities.
func GroupByAdvisory(vulnConnections []*SecurityVulnerabilityConnection) map[string]*AdvisoryWithVulnerabilities {
	result := make(map[string]*AdvisoryWithVulnerabilities)
	for _, vc := range vulnConnections {
		advisory := result[vc.Advisory.ID]
		if advisory == nil {
			advisory = &AdvisoryWithVulnerabilities{
				Advisory: vc.Advisory,
			}
			result[vc.Advisory.ID] = advisory
		}
		advisory.Vulnerabilities = append(advisory.Vulnerabilities, &vc.SecurityVulnerability)
	}
	return result
}
