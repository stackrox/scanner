package features

var (
	// ContinueUnknownOS defines if scanning should continue upon detecting unknown OS.
	ContinueUnknownOS = registerFeature("Enable continuation upon detecting unknown OS", "ROX_CONTINUE_UNKNOWN_OS", true)
)
