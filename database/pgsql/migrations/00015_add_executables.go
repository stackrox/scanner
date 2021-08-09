package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 15,
		Up: migrate.Queries([]string{
			`ALTER TABLE rhelv2_package ADD COLUMN executables TEXT[]`,
			`ALTER TABLE FeatureVersion ADD COLUMN executables TEXT[]`,
		}),
	})
}
