package loaddump

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

	c.RunE = func(_ *cobra.Command, _ []string) error {
		log.Infof("Attempting to open DB at %s:%d", *postgresHost, *postgresPort)
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
		log.Info("Successfully opened DB")

		// We don't want to bother with an in-mem update.
		scratchDir, err := ioutil.TempDir("", "vuln-updater-load-dump")
		if err != nil {
			return errors.Wrap(err, "creating scratch dir")
		}
		log.Info("Updating DB with vuln dump")
		err = vulndump.UpdateFromVulnDump(*dumpFile, scratchDir, db, nil)
		if err != nil {
			return errors.Wrap(err, "updating DB from dump")
		}
		log.Info("All done!")

		return nil
	}

	return c
}
