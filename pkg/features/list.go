package features

var (
	LanguageVulns = registerFeature("Enable language vulnerabilities", "ROX_LANGUAGE_VULNS", true, true)

	ContinueUnknownOS = registerFeature("Enable continuation upon detecting unknown OS", "ROX_CONTINUE_UNKNOWN_OS", false, false)
)
