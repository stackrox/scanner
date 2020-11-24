package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 8,
		Up: migrate.Queries([]string{
			`ALTER TABLE LanguageLayer
		ADD COLUMN removed_components BYTEA NOT NULL;`,
		}),
	})
}
