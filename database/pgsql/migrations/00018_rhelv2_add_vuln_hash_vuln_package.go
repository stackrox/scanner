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
	// Adding vuln_hash to the vuln_package table allows us to relate a vuln_package
	// to the correct vuln row by via vuln_package.vuln_hash = vuln.hash.
	//
	// Note: Keeping the vuln_package.name field is still relevant when deleting vuln_package
	// entries.
	RegisterMigration(migrate.Migration{
		ID: 18,
		Up: migrate.Queries([]string{
			`-- Vulnerability Description
             -- This table holds the vulnerability descriptions with their hash.
			CREATE TABLE IF NOT EXISTS vuln_desc (
				id          BIGSERIAL PRIMARY KEY,
				hash        BYTEA NOT NULL,
				description TEXT,
				UNIQUE (hash)
			);
            -- Move description from vuln to vuln_desc table.
			ALTER TABLE vuln ADD COLUMN desc_hash BYTEA REFERENCES vuln_desc (hash);
			ALTER TABLE vuln DROP COLUMN description;
			CREATE INDEX IF NOT EXISTS vuln_by_desc_idx on vuln (desc_hash);
			-- Add a vuln hash to vuln_package 
			ALTER TABLE vuln_package ADD COLUMN vuln_hash BYTEA NOT NULL`,
		}),
	})
}
