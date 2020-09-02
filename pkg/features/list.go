package features

var (
	LanguageVulns = registerFeature("Enable language vulnerabilities", "LANGUAGE_VULNS", true)

	ContinueUnknownOS = registerFeature("Enable continuation upon detecting unknown OS", "ROX_CONTINUE_UNKNOWN_OS", false)
)
