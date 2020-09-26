package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/stackrox/scanner/cmd/updater/diffdumps"
	"github.com/stackrox/scanner/cmd/updater/ensurediffs"
	"github.com/stackrox/scanner/cmd/updater/generatedump"
	"github.com/stackrox/scanner/cmd/updater/loaddump"
	"github.com/stackrox/scanner/cmd/updater/printstats"

	// Registrations.
	_ "github.com/stackrox/scanner/database/pgsql"
	_ "github.com/stackrox/scanner/ext/vulnsrc/all"
)

func main() {
	c := &cobra.Command{
		Short:        "Commands related to fetching updated vulnerability definitions",
		SilenceUsage: true,
	}

	c.AddCommand(
		diffdumps.Command(),
		ensurediffs.Command(),
		generatedump.Command(),
		loaddump.Command(),
		printstats.Command(),
	)

	if err := c.Execute(); err != nil {
		// No need to log the error, Cobra does it already.
		os.Exit(1)
	}
}
