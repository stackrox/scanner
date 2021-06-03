package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 14,
		Up: migrate.Queries([]string{
			`ALTER TABLE ImageToLayer ADD COLUMN lineage varchar`,
			`ALTER TABLE LanguageLayer ADD COLUMN lineage varchar`,
			`ALTER TABLE Layer ADD COLUMN lineage varchar`,
			`ALTER TABLE Layer_diff_FeatureVersion ADD COLUMN lineage varchar`,
			`ALTER TABLE Layer DROP CONSTRAINT layer_name_key`,
			`ALTER TABLE Layer ADD UNIQUE (name, lineage)`,
		}),
	})
}
