package env

var (
	// LanguageVulns enables language vulnerabilities.
	LanguageVulns = registerBooleanSetting("ROX_LANGUAGE_VULNS", true, AllowWithoutRox())

	// SkipPeerValidation skips peer certificate validation (typically used for testing).
	SkipPeerValidation = registerBooleanSetting("ROX_SKIP_PEER_VALIDATION", false)
)
