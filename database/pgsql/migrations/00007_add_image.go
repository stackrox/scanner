package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 7,
		Up: migrate.Queries([]string{
			`CREATE TABLE IF NOT EXISTS ImageToLayer(
		layer varchar,
		name varchar,
		sha  varchar,
		PRIMARY KEY( sha, name ));`,
		}),
	})
}
