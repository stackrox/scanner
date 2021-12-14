package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE FeatureVersion ADD COLUMN IF NOT EXISTS executable_to_dependencies BYTEA`,
			`ALTER TABLE FeatureVersion ADD COLUMN IF NOT EXISTS library_to_dependencies BYTEA`,
			`ALTER TABLE FeatureVersion DROP COLUMN IF EXISTS executables`,
		}),
	})
}
