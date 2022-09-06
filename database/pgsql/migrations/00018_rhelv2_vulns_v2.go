package migrations

import "github.com/remind101/migrate"

func init() {
	// Prior to this migration, a vuln_package row was tied back to its related vuln row
	// via the matching vuln_package.name and vuln.name. This, however, may result in
	// multiple rows in vuln being returned. For example, for CVE-2022-1650, there are several
	// affected packages, each with a potentially different severity than others.
	// So, if a vuln_package related to CVE-2022-1650 is desired, several rows may be returned,
	// as there are several entries in vuln tied to CVE-2022-1650.
	//
	// This migration replaces the old vuln and vuln_package tables with vuln_v2 and vuln_description.
	// This is meant to align us more with Clair v4,
	// https://github.com/quay/claircore/blob/v1.4.6/datastore/postgres/migrations/matcher/01-init.sql#L41.
	// We opt to separate the vuln description into a separate table to conserve disk space.
	RegisterMigration(migrate.Migration{
		ID: 18,
		Up: migrate.Queries([]string{
			`-- VulnV2 is a write-once table of vulnerabilities.
		CREATE TABLE IF NOT EXISTS vuln_v2 (
			id               BIGSERIAL PRIMARY KEY,
			hash             BYTEA NOT NULL,
			name             TEXT,
			title            TEXT,
			description_hash BYTEA NOT NULL,
			issued           timestamptz,
			updated          timestamptz,
			link             TEXT,
			severity         TEXT,
			cvss3            TEXT,
			cvss2            TEXT,
			package_name     TEXT,
			package_module   TEXT,
			package_arch     TEXT,
			cpe              TEXT,
			fixed_in_version TEXT,
			arch_operation   TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX IF NOT EXISTS vuln_v2_lookup_idx on vuln_v2 (name);
		CREATE INDEX IF NOT EXISTS vuln_v2_package_lookup_idx on vuln_v2 (package_name, package_module, cpe);
		

		-- VulnDescription
		-- This table contains the description for each vulnerability.
		CREATE TABLE IF NOT EXISTS vuln_description (
			id          BIGSERIAL PRIMARY KEY,
			hash        BYTEA NOT NULL,
			description TEXT,
			UNIQUE (hash)
		);
		CREATE INDEX IF NOT EXISTS vuln_description_lookup_idx on vuln_description (hash);`,
			`DROP TABLE IF EXISTS vuln;`,
			`DROP TABLE IF EXISTS vuln_package;`,
		}),
	})
}
