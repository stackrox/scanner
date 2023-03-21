package env

import (
	"time"
)

var (
	// NodeScanningCacheDuration defines the time after which a cached inventory is considered outdated. Defaults to 90% of NodeScanningInterval.
	NodeScanningCacheDuration = registerDurationSetting("ROX_NODE_SCANNING_CACHE_TIME", time.Duration(3*time.Hour))

	// NodeScanningInitialBackoff defines the initial time in seconds a Node scan will be delayed if a backoff file is found
	NodeScanningInitialBackoff = registerDurationSetting("ROX_NODE_SCANNING_INITIAL_BACKOFF", 30*time.Second)

	// NodeScanningMaxBackoff is the upper boundary of backoff. Defaults to 5m in seconds, being 50% of Kubernetes restart policy stability timer.
	NodeScanningMaxBackoff = registerDurationSetting("ROX_NODE_SCANNING_MAX_BACKOFF", 300*time.Second)
)
