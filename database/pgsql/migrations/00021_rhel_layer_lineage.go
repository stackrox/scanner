package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 21,
		Up: migrate.Queries([]string{

			// The lineage column mimics the existing `layer` table. The parent_lineage column is used
			// instead of equivalent parent_id column from the 'layer' table to avoid an extra query
			// on insert (which would be necessary to determine the parent id).
			`ALTER TABLE rhelv2_layer ADD COLUMN IF NOT EXISTS lineage varchar;`,
			`ALTER TABLE rhelv2_layer ADD COLUMN IF NOT EXISTS parent_lineage varchar`,

			// Create a new unique constraint that includes lineage (and drop the old constraint)
			`ALTER TABLE rhelv2_layer ADD CONSTRAINT rhelv2_layer_hash_lineage_key UNIQUE (hash, lineage)`,
			`ALTER TABLE rhelv2_layer DROP CONSTRAINT IF EXISTS rhelv2_layer_hash_key`,

			// Create additional index to improve performance when recursively traversing parents.
			`CREATE INDEX IF NOT EXISTS rhelv2_layer_parent_idx on rhelv2_layer (parent_hash, parent_lineage)`,
		}),
	})
}
