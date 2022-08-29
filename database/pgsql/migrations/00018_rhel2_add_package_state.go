package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 18,
		Up: migrate.Queries([]string{
			`ALTER TABLE rhelv2_package ADD COLUMN IF NOT EXISTS resolution_state VARCHAR(64)`,
		}),
	})
}
