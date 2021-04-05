package pgsql

import (
	"database/sql"

	"github.com/lib/pq"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
)

func (pgSQL *pgSQL) InsertRHELv2Layer(layer *database.RHELv2Layer) error {
	tx, err := pgSQL.Begin()
	if err != nil {
		return handleError("InsertRHELv2Layer.Begin()", err)
	}

	if err := pgSQL.insertRHELv2Layer(tx, layer); err != nil {
		utils.IgnoreError(tx.Rollback)
		return err
	}

	if err := pgSQL.insertRHELv2Packages(tx, layer.Hash, layer.Pkgs); err != nil {
		utils.IgnoreError(tx.Rollback)
		return err
	}

	if err := tx.Commit(); err != nil {
		utils.IgnoreError(tx.Rollback)
		return handleError("InsertRHELv2Layer.Commit()", err)
	}

	return nil
}

func (pgSQL *pgSQL) insertRHELv2Layer(tx *sql.Tx, layer *database.RHELv2Layer) error {
	const (
		insertLayer = `
		INSERT INTO rhelv2_layer (hash, parent_hash, dist, cpes)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (hash) DO NOTHING;
		`
	)

	_, err := tx.Exec(insertLayer, layer.Hash, layer.ParentHash, layer.Dist, pq.Array(layer.CPEs))
	return err
}

func (pgSQL *pgSQL) insertRHELv2Packages(tx *sql.Tx, layer string, pkgs []*database.Package) error {
	const (
		insert = ` 
		INSERT INTO package (name, version, module, arch)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name, version, module, arch) DO NOTHING;
		`

		insertWith = `
		WITH package AS (
			SELECT id AS package_id
			FROM package
			WHERE name = $1
			  AND version = $2
			  AND module = $3
			  AND arch = $4
		),
		layer AS (
			SELECT id AS layer_id
			FROM rhelv2_layer
			WHERE rhelv2_layer.hash = $5
		)
		INSERT
		INTO package_scanartifact (layer_id, package_id)
		VALUES ((SELECT layer_id FROM layer), (SELECT package_id FROM package))
		ON CONFLICT (layer_id, package_id) DO NOTHING;
		`
	)

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insert, pkg.Name, pkg.Version, pkg.Module, pkg.Arch)
		if err != nil {
			return err
		}
	}

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insertWith,
			pkg.Name,
			pkg.Version,
			pkg.Module,
			pkg.Arch,
			layer,
		)

		if err != nil {
			return err
		}
	}

	return nil
}
