package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 9,
		Up: migrate.Queries([]string{
			`ALTER TABLE Layer
		ADD COLUMN distroless bool DEFAULT false; `,
		}),
	})
}
