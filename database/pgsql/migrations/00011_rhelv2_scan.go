package migrations

import "github.com/remind101/migrate"

// TODO: influenced by claircore.

func init() {
	RegisterMigration(migrate.Migration{
		ID: 11,
		Up: migrate.Queries([]string{
			`--- RHELv2 Layer
		--- an identity table consisting of a content addressable layer hash
		CREATE TABLE IF NOT EXISTS rhelv2_layer (
			id          BIGSERIAL PRIMARY KEY,
	    	hash        TEXT,
			parent_hash TEXT NOT NULL DEFAULT '',
			dist        TEXT,
			cpes        TEXT[],
			UNIQUE (hash)
		);

		--- Package
		--- a unique package discovered by a scanner
		CREATE TABLE IF NOT EXISTS package (
			id      BIGSERIAL PRIMARY KEY,
			name    TEXT NOT NULL,
			version TEXT NOT NULL DEFAULT '',
			module  TEXT NOT NULL DEFAULT '',
			arch    TEXT NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX IF NOT EXISTS package_unique_idx ON package (name, version, module, arch);

		--- PackageScanArtifact
		--- A relation linking discovered packages with the layer hash it was found
		CREATE TABLE IF NOT EXISTS package_scanartifact (
			layer_id   BIGINT REFERENCES rhelv2_layer(id),
			package_id BIGINT REFERENCES package(id),
			PRIMARY KEY (layer_id, package_id)
		);
		CREATE INDEX IF NOT EXISTS package_scanartifact_lookup_idx ON package_scanartifact (layer_id);`,
		}),
	})
}
