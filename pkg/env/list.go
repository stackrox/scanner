package env

var (
	// LanguageVulns enables language vulnerabilities.
	LanguageVulns = RegisterBooleanSetting("ROX_LANGUAGE_VULNS", true, AllowWithoutRox())

	// SkipPeerValidation skips peer certificate validation (typically used for testing).
	SkipPeerValidation = RegisterBooleanSetting("ROX_SKIP_PEER_VALIDATION", false)

	// LiteMode enables lite-mode.
	LiteMode = RegisterBooleanSetting("ROX_LITE_MODE", false)
)
