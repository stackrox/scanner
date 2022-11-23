package features

var (
	// ContinueUnknownOS defines if scanning should continue upon detecting unknown OS.
	ContinueUnknownOS = registerFeature("Enable continuation upon detecting unknown OS", "ROX_CONTINUE_UNKNOWN_OS", true)
	// RHEL9Scanning enables support for scanning RHEL9-based images.
	RHEL9Scanning = registerFeature("Enable support for scanning RHEL9 images", "ROX_RHEL9_SCANNING", true)
	// RHCOSNodeScanning enables phase 1 functions of "Full host level vulnerability scanning for RHCOS nodes" (ROX-10818)
	RHCOSNodeScanning = registerFeature("Enable RHCOS node scanning of OS and installed packages", "ROX_RHCOS_NODE_SCANNING", true)
)
