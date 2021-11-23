package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE FeatureVersion ADD COLUMN lib_deps_to_libs JSONB`,
			`ALTER TABLE FeatureVersion ADD COLUMN lib_deps_to_execs JSONB`,
		}),
	})
}
