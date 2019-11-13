package loaddump

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/vulndump"
)

func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "load-dump",
	}

	postgresHost := c.Flags().String("postgres-host", "127.0.0.1", "postgres host")
	postgresPort := c.Flags().Int("postgres-port", 5432, "postgres port")
	dumpFile := c.Flags().String("dump-file", "", "path to dump file")
	utils.Must(c.MarkFlagRequired("dump-file"))
	_ = dumpFile

	c.RunE = func(_ *cobra.Command, _ []string) error {
		db, err := database.OpenWithRetries(database.RegistrableComponentConfig{
			Type: "pgsql",
			Options: map[string]interface{}{
				"source": fmt.Sprintf("host=%s port=%d user=postgres sslmode=disable statement_timeout=60000", *postgresHost, *postgresPort),
			},
		}, 5, 10*time.Second)
		if err != nil {
			return errors.Wrap(err, "opening DB")
		}
		defer db.Close()

		// We don't want to bother with an in-mem update.
		err = vulndump.UpdateFromVulnDump(*dumpFile, db, func(_ string) error {
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "updating DB from dump")
		}

		return nil
	}

	return c
}
