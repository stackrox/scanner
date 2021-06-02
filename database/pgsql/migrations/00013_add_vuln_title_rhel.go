package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 13,
		Up: migrate.Queries([]string{
			`ALTER TABLE vuln ADD COLUMN title TEXT NOT NULL DEFAULT ''`,
		}),
	})
}
