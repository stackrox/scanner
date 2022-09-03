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
			`ALTER TABLE vuln_package ADD COLUMN vuln_hash BYTEA NOT NULL`,
		}),
	})
}
