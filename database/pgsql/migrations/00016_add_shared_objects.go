package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE FeatureVersion ADD COLUMN dependency_to_executables JSONB`,
			`ALTER TABLE FeatureVersion ADD COLUMN libraries TEXT[]`,
			`ALTER TABLE FeatureVersion ADD COLUMN dependency_to_libraries JSONB`,
		}),
	})
}
