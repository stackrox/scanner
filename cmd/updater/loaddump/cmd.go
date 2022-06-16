package loaddump

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/vulndump"
)

// Command defines the `load-dump` command.
func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "load-dump",
	}

	var (
		postgresHost string
		postgresPort int
		dumpFile     string
	)

	c.RunE = func(_ *cobra.Command, _ []string) error {
		log.SetLevel(log.DebugLevel)
		log.Infof("Attempting to open DB at %s:%d", postgresHost, postgresPort)
		db, err := database.OpenWithRetries(database.RegistrableComponentConfig{
			Type: "pgsql",
			Options: map[string]interface{}{
				"source": fmt.Sprintf("host=%s port=%d user=postgres sslmode=disable statement_timeout=60000", postgresHost, postgresPort),
			},
		}, false, 5, 10*time.Second)
		if err != nil {
			return errors.Wrap(err, "opening DB")
		}
		defer db.Close()
		log.Info("Successfully opened DB")

		log.Info("Updating DB with vuln dump")
		err = vulndump.UpdateFromVulnDump(dumpFile, db, 1*time.Hour, "updater", nil, nil)
		if err != nil {
			return errors.Wrap(err, "updating DB from dump")
		}
		log.Info("All done!")

		return nil
	}

	c.Flags().StringVar(&postgresHost, "postgres-host", "127.0.0.1", "postgres host")
	c.Flags().IntVar(&postgresPort, "postgres-port", 5432, "postgres port")
	c.Flags().StringVar(&dumpFile, "dump-file", "", "path to dump file")
	utils.Must(c.MarkFlagRequired("dump-file"))

	return c
}
