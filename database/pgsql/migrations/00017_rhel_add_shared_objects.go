package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE rhelv2_package ADD COLUMN IF NOT EXISTS executable_to_dependencies BYTEA`,
			`ALTER TABLE rhelv2_package ADD COLUMN IF NOT EXISTS library_to_dependencies BYTEA`,
			`ALTER TABLE rhelv2_package DROP COLUMN IF EXISTS executables`,
		}),
	})
}
