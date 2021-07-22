package features

var (
	// ContinueUnknownOS defines if scanning should continue upon detecting unknown OS.
	ContinueUnknownOS = registerFeature("Enable continuation upon detecting unknown OS", "ROX_CONTINUE_UNKNOWN_OS", true)

	// ActiveVulnMgmt defines if features related to Active Vuln Mgmt should be enabled.
	ActiveVulnMgmt = registerFeature("Enable features related to Active Vulnerability Management", "ROX_ACTIVE_VULN_MGMT", false)
)
