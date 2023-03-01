package main

import "github.com/stackrox/scanner/pkg/env"

var (
	nodeName = env.RegisterSetting("ROX_NODE_NAME", env.WithDefault("unset"))

	nodeScannerHTTPPort = env.RegisterSetting("ROX_NODE_SCAN_SERVER_PORT", env.WithDefault("8080"))
)
