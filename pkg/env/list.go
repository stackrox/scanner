package env

import "time"

var (
	// LanguageVulns enables language vulnerabilities.
	LanguageVulns = RegisterBooleanSetting("ROX_LANGUAGE_VULNS", true, AllowWithoutRox())

	// SkipPeerValidation skips peer certificate validation (typically used for testing).
	// When disabled, only Central ingress is allowed, by default. See SlimMode and
	// OpenshiftAPI for other ingress controls.
	SkipPeerValidation = RegisterBooleanSetting("ROX_SKIP_PEER_VALIDATION", false)

	// SlimMode enables slim-mode. When enabled, Scanner only supports a subset of APIs,
	// and only Sensor ingress is allowed.
	// If SkipPeerValidation or OpenshiftAPI is enabled, the ingress implications are ignored.
	SlimMode = RegisterBooleanSetting("ROX_SLIM_MODE", false)

	// OpenshiftAPI indicates Scanner is running in an OpenShift environment.
	// When set to "true", ingress is allowed from both Central and Sensor.
	// This is ignored if SkipPeerValidation is enabled.
	// This variable was copied over from the stackrox repo.
	OpenshiftAPI = RegisterBooleanSetting("ROX_OPENSHIFT_API", false)

	// NodeName is used when running Scanner in Node Inventory mode. This should be set by
	// Kubernetes in the Secured Cluster.
	NodeName = RegisterSetting("ROX_NODE_NAME")

	// NodeScanningCacheDuration defines the time after which a cached inventory is considered outdated. Defaults to 90% of NodeScanningInterval.
	NodeScanningCacheDuration = registerDurationSetting("ROX_NODE_SCANNING_CACHE_TIME", 216*time.Minute)

	// NodeScanningInitialBackoff defines the initial time in seconds a Node scan will be delayed if a backoff file is found
	NodeScanningInitialBackoff = registerDurationSetting("ROX_NODE_SCANNING_INITIAL_BACKOFF", 30*time.Second)

	// NodeScanningMaxBackoff is the upper boundary of backoff. Defaults to 5m in seconds, being 50% of Kubernetes restart policy stability timer.
	NodeScanningMaxBackoff = registerDurationSetting("ROX_NODE_SCANNING_MAX_BACKOFF", 300*time.Second)
)
