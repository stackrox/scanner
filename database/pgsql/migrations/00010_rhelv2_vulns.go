///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 10,
		Up: migrate.Queries([]string{
			`-- Vuln is a write-once table of vulnerabilities.
		CREATE TABLE IF NOT EXISTS vuln (
			id               BIGSERIAL PRIMARY KEY,
			hash             BYTEA NOT NULL,
			name             TEXT,
			description      TEXT,
			issued           timestamptz,
			updated          timestamptz,
			link             TEXT,
			severity         TEXT,
			cvss3            TEXT,
			cvss2            TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX IF NOT EXISTS vuln_lookup_idx on vuln (name);

		-- VulnPackage
		-- This table contains all the aspects of a vulnerability used to identify if
		-- a given package is actually vulnerable (save for arch_operation).
		-- This table is structured to contain on the field necessary for identifying if a package is vulnerable,
		-- so be sure to know what you are doing before modifying this table.
		CREATE TABLE IF NOT EXISTS vuln_package (
			id               BIGSERIAL PRIMARY KEY,
			hash             BYTEA NOT NULL,
			vuln_hash        BYTEA NOT NULL,
			name             TEXT,
			package_name     TEXT,
			package_module   TEXT,
			package_arch     TEXT,
			cpe              TEXT,
			fixed_in_version TEXT,
			arch_operation   TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX IF NOT EXISTS vuln_package_lookup_idx on vuln_package (package_name, package_module, cpe);`,
		}),
	})
}
