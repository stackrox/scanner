package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 12,
		Up: migrate.Queries([]string{
			`ALTER TABLE ImageToLayer ADD COLUMN uncertified_rhel boolean`,
			`UPDATE ImageToLayer SET uncertified_rhel = false`,
			`ALTER TABLE ImageToLayer DROP CONSTRAINT ImageToLayer_pkey`,
			`ALTER TABLE ImageToLayer ADD PRIMARY KEY (sha, name, uncertified_rhel)`,
		}),
	})
}
