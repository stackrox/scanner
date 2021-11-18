package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 16,
		Up: migrate.Queries([]string{
			`ALTER TABLE FeatureVersion ADD COLUMN provides TEXT[]`,
			`ALTER TABLE FeatureVersion ADD COLUMN depends: JSONB`,
		}),
	})
}
