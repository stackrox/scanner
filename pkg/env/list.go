package env

import "time"

const (
	// DefaultMaxGrpcConcurrentStreams is the minimum value for concurrent streams recommended by the HTTP/2 spec
	DefaultMaxGrpcConcurrentStreams = 100
)

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

	// NodeName is used when running Scanner in Node Inventory mode. This should be set by
	// Kubernetes in the Secured Cluster.
	NodeName = RegisterSetting("ROX_NODE_NAME")

	// NodeScanningCacheDuration defines the time after which a cached inventory is considered outdated. Defaults to 90% of NodeScanningInterval.
	NodeScanningCacheDuration = registerDurationSetting("ROX_NODE_SCANNING_CACHE_TIME", 216*time.Minute)

	// NodeScanningInitialBackoff defines the initial time in seconds a Node scan will be delayed if a backoff file is found
	NodeScanningInitialBackoff = registerDurationSetting("ROX_NODE_SCANNING_INITIAL_BACKOFF", 30*time.Second)

	// NodeScanningMaxBackoff is the upper boundary of backoff. Defaults to 5m in seconds, being 50% of Kubernetes restart policy stability timer.
	NodeScanningMaxBackoff = registerDurationSetting("ROX_NODE_SCANNING_MAX_BACKOFF", 300*time.Second)

	// ActiveVulnMgmt is the same flag in Central that determines if active vulnerability management should be
	// enabled and executables should be pulled from the database
	ActiveVulnMgmt = RegisterBooleanSetting("ROX_ACTIVE_VULN_MGMT", false)

	// MaxGrpcConcurrentStreams configures the maximum number of HTTP/2 streams to use with gRPC
	MaxGrpcConcurrentStreams = RegisterIntegerSetting("ROX_GRPC_MAX_CONCURRENT_STREAMS", DefaultMaxGrpcConcurrentStreams)

	// NVDFeedLoader when true will cause the loader to pull NVD data using
	// the NVD 2.0 Data Feeds. If false, the loader will pull from the NVD 2.0 API.
	NVDFeedLoader = RegisterBooleanSetting("ROX_NVD_FEED_LOADER", false)

	// RHLineage when true will cause all parent layers (a.k.a lineage) to be considered when
	// storing scan results for RHEL image layers.
	//
	// Setting this to false will cause known scan inaccuracies and should only be disabled as a
	// temporary measure to address unforeseen stability issues.
	RHLineage = RegisterBooleanSetting("ROX_RHEL_LINEAGE", true)
)
