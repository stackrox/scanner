package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 9,
		Up: migrate.Queries([]string{
			`-- Needed for uuid generation in-database.
		-- The inline function makes for a nicer error message.
		DO $$
		DECLARE
			hint text;
			detail text;
			code text;
		BEGIN
			EXECUTE 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"';
		EXCEPTION WHEN OTHERS THEN
			-- https://www.postgresql.org/docs/current/plpgsql-control-structures.html#PLPGSQL-EXCEPTION-DIAGNOSTICS
			GET STACKED DIAGNOSTICS
				code = RETURNED_SQLSTATE,
				detail = PG_EXCEPTION_DETAIL,
				hint = PG_EXCEPTION_HINT;
			RAISE EXCEPTION USING
				MESSAGE = 'Please load the "uuid-ossp" extension.',
				ERRCODE = code,
				DETAIL = detail,
				HINT = hint;
		END;
		$$ LANGUAGE plpgsql;
		-- Vuln is a write-once table of vulnerabilities.
		--
		-- Updaters should attempt to insert vulnerabilities and on success or
		-- collision, insert a row into ou_vuln.
		CREATE TABLE IF NOT EXISTS vuln (
			id               BIGSERIAL PRIMARY KEY,
			hash             BYTEA NOT NULL,
			name             TEXT,
			description      TEXT,
			issued           timestamptz,
			links            TEXT,
			severity         TEXT,
			cvss3            TEXT,
			cvss2            TEXT,
			package_name     TEXT,
			package_version  TEXT,
			package_module   TEXT,
			package_arch     TEXT,
			package_kind     TEXT,
			dist_id          TEXT,
			dist_version_id  TEXT,
			dist_cpe         TEXT,
			cpe              TEXT,
			fixed_in_version TEXT,
			arch_operation   TEXT,
			UNIQUE (hash)
		);
		-- this index is tuned for the application. if you change this measure pre and post
		-- change query speeds when generating vulnerability reports.
		CREATE INDEX vuln_lookup_idx on vuln (package_name, dist_id,
											  dist_version_id, package_module,
											  cpe, dist_cpe);`,
		}),
	})
}
