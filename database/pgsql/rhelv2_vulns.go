package pgsql

import (
	"database/sql"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
)

func (pgSQL *pgSQL) GetRHELv2Vulns(records []*database.RHELv2Record) ([]*database.RHELv2Vulnerability, error) {
	vulnMap := make(map[int]*database.RHELv2Vulnerability)

	tx, err := pgSQL.Begin()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.Pkg != nil && record.Pkg.Name != "" {
			matchedVulns, err := pgSQL.getRHELv2Vulns(tx, record)
			if err != nil {
				utils.IgnoreError(tx.Rollback)
				return nil, err
			}
			for _, matched := range matchedVulns {
				vulnMap[matched.ID] = matched
			}
		}
	}

	vulns := make([]*database.RHELv2Vulnerability, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func (pgSQL *pgSQL) getRHELv2Vulns(tx *sql.Tx, record *database.RHELv2Record) ([]*database.RHELv2Vulnerability, error) {
	const (
		queryWithoutSource = `
			SELECT
				vuln.id,
				vuln_description.description,
				vuln.links,
				vuln.issued,
				vuln.severity,
				vuln.cvss3,
				vuln.cvss2,
				vuln.package_name,
				vuln.package_version,
				vuln.package_arch,
				vuln.arch_operation,
				vuln.fixed_in_version
			FROM
  				vuln
  				LEFT JOIN vuln_description ON
    				vuln.name = vuln_description.name
			WHERE
				vuln.package_name = $1
				AND vuln.package_kind = $2
				AND vuln.package_module = $3
				AND vuln.cpe = $4;
		`

		queryWithSource = `
			SELECT
				vuln.id,
			    vuln.name,
				vuln_description.description,
				vuln.links,
				vuln.issued,
				vuln.severity,
				vuln.cvss3,
				vuln.cvss2,
				vuln.package_name,
				vuln.package_version,
				vuln.package_arch,
				vuln.arch_operation,
				vuln.fixed_in_version
			FROM
  				vuln
  				LEFT JOIN vuln_description ON
    				vuln.name = vuln_description.name
			WHERE
				(vuln.package_name = $1 AND vuln.package_kind = $2)
				OR (vuln.package_name = $3 AND vuln.package_kind = $4)
				AND vuln.package_module = $5
				AND vuln.cpe = $6;
		`
	)

	var rows *sql.Rows
	var err error

	if record.Pkg.Source != nil && record.Pkg.Source.Name != "" {
		rows, err = tx.Query(queryWithSource, record.Pkg.Name, record.Pkg.Kind, record.Pkg.Source.Name, record.Pkg.Source.Kind, record.Pkg.Module, record.CPE)
	} else {
		rows, err = tx.Query(queryWithoutSource, record.Pkg.Name, record.Pkg.Kind, record.Pkg.Module, record.CPE)
	}

	if err != nil {
		return nil, err
	}
	defer utils.IgnoreError(rows.Close)

	var vulns []*database.RHELv2Vulnerability

	for rows.Next() {
		var vuln database.RHELv2Vulnerability
		err := rows.Scan(
			&vuln.ID,
			&vuln.Name,
			&vuln.Description,
			&vuln.
		)
	}
}
