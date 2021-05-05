package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 12,
		Up: migrate.Queries([]string{
			`ALTER TABLE ImageToLayer
		ADD COLUMN uncertified_rhel boolean`,
		}),
	})
}
