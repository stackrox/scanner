package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE FeatureVersion ADD COLUMN library_to_dependencies JSONB`,
			`ALTER TABLE FeatureVersion ADD COLUMN dependency_to_executables JSONB`,
		}),
	})
}
