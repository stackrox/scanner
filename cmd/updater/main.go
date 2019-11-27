package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/scanner/cmd/updater/diffdumps"
	"github.com/stackrox/scanner/cmd/updater/generatedump"
	"github.com/stackrox/scanner/cmd/updater/loaddump"

	// Registrations.
	_ "github.com/stackrox/scanner/database/pgsql"
	_ "github.com/stackrox/scanner/ext/vulnsrc/all"
)

const (
	proxyConfigPath = "/run/secrets/stackrox.io/proxy-config"
	proxyConfigFile = "config.yaml"
)

func init() {
	proxy.UseWithDefaultTransport()
}

func main() {
	proxy.WatchProxyConfig(context.Background(), proxyConfigPath, proxyConfigFile, true)

	c := &cobra.Command{
		Short:        "Commands related to fetching updated vulnerability definitions",
		SilenceUsage: true,
	}

	c.AddCommand(
		diffdumps.Command(),
		generatedump.Command(),
		loaddump.Command(),
	)

	if err := c.Execute(); err != nil {
		// No need to log the error, Cobra does it already.
		os.Exit(1)
	}
}
