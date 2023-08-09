package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 20,
		Up: migrate.Queries([]string{
			`ALTER TABLE LanguageLayer DROP CONSTRAINT IF EXISTS languagelayer_pkey`,
			`ALTER TABLE LanguageLayer DROP CONSTRAINT IF EXISTS languagelayer_layer_name_key`,
			`ALTER TABLE LanguageLayer ADD PRIMARY KEY (layer_name, lineage)`,
		}),
	})
}
