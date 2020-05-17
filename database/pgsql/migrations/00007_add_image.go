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

			`CREATE TABLE IF NOT EXISTS LanguageLayer (
		layer_id int NOT NULL,
        layer_name VARCHAR(128) NOT NULL,
        component_data BYTEA NOT NULL,
        PRIMARY KEY( layer_id, layer_name ));`,
		}),
	})
}
