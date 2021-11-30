package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			// TODO(cdu): Add migration code from executables to executable_to_dependencies
			`ALTER TABLE FeatureVersion ADD COLUMN executable_to_dependencies JSONB`,
			`ALTER TABLE FeatureVersion ADD COLUMN library_to_dependencies JSONB`,
		}),
	})
}
