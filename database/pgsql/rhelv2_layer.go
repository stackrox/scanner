///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

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
	_, err := tx.Exec(insertRHELv2Layer, layer.Hash, layer.ParentHash, layer.Dist, pq.Array(layer.CPEs))
	return err
}

func (pgSQL *pgSQL) insertRHELv2Packages(tx *sql.Tx, layer string, pkgs []*database.RHELv2Package) error {
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insertRHELv2Package, pkg.Name, pkg.Version, pkg.Module, pkg.Arch)
		if err != nil {
			return err
		}
	}

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insertRHELv2PackageArtifact,
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
