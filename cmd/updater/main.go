package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/scanner/cmd/updater/generatedump"

	// Registrations.
	_ "github.com/stackrox/scanner/database/pgsql"
	_ "github.com/stackrox/scanner/ext/vulnsrc/all"
)

func main() {
	c := &cobra.Command{
		Use: "Commands related to fetching updated vulnerability definitions",
	}

	c.AddCommand(
		generatedump.Command(),
	)

	if err := c.Execute(); err != nil {
		logrus.WithError(err).Error("Command execution failed")
		os.Exit(1)
	}
}
