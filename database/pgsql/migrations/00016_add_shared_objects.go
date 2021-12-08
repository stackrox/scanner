package migrations

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/remind101/migrate"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
)

const (
	declareFmt = "DECLARE %s CURSOR FOR SELECT id, executables FROM %s ORDER BY id"
	updateFmt = "UPDATE %s SET executable_to_dependencies = $2 WHERE id = $1"
)

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: func(tx *sql.Tx) error {
			// Create new columns
			if err := addColumn(tx, "FeatureVersion", "executable_to_dependencies"); err != nil {
				return err
			}
			if err := addColumn(tx, "FeatureVersion", "library_to_dependencies"); err != nil {
				return err
			}
			if err := addColumn(tx, "rhelv2_package", "executable_to_dependencies"); err != nil {
				return err
			}
			if err := addColumn(tx, "rhelv2_package", "library_to_dependencies"); err != nil {
				return err
			}
			// Convert executables to executable_to_dependencies
			if err := moveExecutables(tx, "FeatureVersion"); err != nil {
				return err
			}
			if err := moveExecutables(tx, "rhelv2_package"); err != nil {
				return err
			}
			// Drop column executables
			_, err := tx.Exec("ALTER TABLE FeatureVersion DROP COLUMN IF EXISTS executables")
			_, err = tx.Exec("ALTER TABLE rhelv2_package DROP COLUMN IF EXISTS executables")
			return err
		},
	})
}

func addColumn(tx *sql.Tx, table string, column string) error {
	_, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s JSONB", table, column))
	return err
}

func moveExecutables(tx *sql.Tx, table string) error {
	cursor := fmt.Sprintf("%s_cursor", table)
	if _, err := tx.Exec(fmt.Sprintf(declareFmt, cursor, table)); err != nil {
		return err
	}
	updateExec := fmt.Sprintf(updateFmt, table)
	defer tx.Exec(fmt.Sprintf("CLOSE %s", cursor))
	for {
		var id string
		var executables []string
		if err := tx.QueryRow(
			fmt.Sprintf("FETCH NEXT FROM %s", cursor),
		).Scan(&id, pq.Array(&executables)); err != nil {
			if err == sql.ErrNoRows {
				// End of rows.
				break
			}
			return err
		}

		// Update an existing layer.
		if _, err := tx.Exec(updateExec, id, convert(executables)); err != nil {
			return err
		}
	}
	return nil
}

func convert(executables []string) database.StringToStringsMap {
	stringMap := make(database.StringToStringsMap, len(executables))
	for _, exec := range executables {
		stringMap[exec] = set.NewStringSet()
	}
	return stringMap
}
