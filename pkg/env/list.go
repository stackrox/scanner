package env

var (
	// LanguageVulns enables language vulnerabilities.
	LanguageVulns = RegisterBooleanSetting("ROX_LANGUAGE_VULNS", true, AllowWithoutRox())

	// SkipPeerValidation skips peer certificate validation (typically used for testing).
	// When disabled, only Central ingress is allowed, by default. See SlimMode and
	// LocalScanning for other ingress controls.
	SkipPeerValidation = RegisterBooleanSetting("ROX_SKIP_PEER_VALIDATION", false)

	// SlimMode enables slim-mode. If SkipPeerValidation is disabled,
	// only Sensor ingress is allowed.
	// If LocalScanning is enabled, this is ignored.
	SlimMode = RegisterBooleanSetting("ROX_SLIM_MODE", false)

	// LocalScanning enables both Central and Sensor ingress instead of just Central.
	// If SkipPeerValidation is enabled, this is ignored.
	LocalScanning = RegisterBooleanSetting("ROX_LOCAL_SCANNING", false)
)
