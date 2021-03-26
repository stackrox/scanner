package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 10,
		Up: migrate.Queries([]string{
			`--- Package
		--- a unique package discovered by a scanner
		CREATE TABLE IF NOT EXISTS package (
			id      BIGSERIAL PRIMARY KEY,
			name    TEXT NOT NULL,
			kind    TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',
			module  TEXT NOT NULL DEFAULT '',
			arch    TEXT NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX IF NOT EXISTS package_unique_idx ON package (name, version, kind, module, arch);

		--- RHELv2 Layer
    	--- an identity table consisting of a content addressable layer hash
    	CREATE TABLE IF NOT EXISTS rhelv2_layer (
			id   BIGSERIAL PRIMARY KEY,
        	hash TEXT,
			dist TEXT,
			
			UNIQUE (hash)
    	);`,
		}),
	})
}
