package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 19,
		Up: migrate.Queries([]string{
			`ALTER TABLE vuln_v2 ADD COLUMN IF NOT EXISTS package_resolution_state TEXT`,
		}),
	})
}
