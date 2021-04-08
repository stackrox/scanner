package migrations

import "github.com/remind101/migrate"

///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////
func init() {
	RegisterMigration(migrate.Migration{
		ID: 10,
		Up: migrate.Queries([]string{
			`-- Vuln is a write-once table of vulnerabilities.
		CREATE TABLE IF NOT EXISTS vuln (
			id               BIGSERIAL PRIMARY KEY,
			hash             BYTEA NOT NULL,
			name             TEXT,
			issued           timestamptz,
			updated          timestamptz,
			links            TEXT,
			severity         TEXT,
			cvss3            TEXT,
			cvss2            TEXT,
			package_name     TEXT,
			package_module   TEXT,
			package_arch     TEXT,
			package_kind     TEXT,
			cpe              TEXT,
			fixed_in_version TEXT,
			arch_operation   TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX vuln_lookup_idx on vuln (package_name, package_module, cpe);

		-- Description may be rather large.
		-- It'd be best to save just one version of the description per vulnerability
		-- to save space. Hashing here as descriptions may be larger than BTree indexes allow.
		CREATE TABLE IF NOT EXISTS vuln_description (
			id          BIGSERIAL PRIMARY KEY,
			hash        BYTEA NOT NULL,
			name        TEXT,
			description TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX vuln_description_lookup_idx on vuln_description (name);`,
		}),
	})
}
