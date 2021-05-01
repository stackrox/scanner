///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package pgsql

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/commonerr"
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

func (pgSQL *pgSQL) GetRHELv2Layers(layerHash string) ([]*database.RHELv2Layer, error) {
	tx, err := pgSQL.BeginTx(context.Background(), &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, handleError("GetRHELv2Layers.Begin()", err)
	}

	rows, err := tx.Query(searchRHELv2Layers, layerHash)
	if err != nil {
		return nil, err
	}
	defer utils.IgnoreError(rows.Close)

	var layers []*database.RHELv2Layer

	for rows.Next() {
		var (
			rhelv2Layer database.RHELv2Layer
			cpes        []string
		)
		if err := rows.Scan(&rhelv2Layer.ID, &rhelv2Layer.Hash, &rhelv2Layer.Dist, pq.Array(&cpes)); err != nil {
			utils.IgnoreError(tx.Rollback)
			return nil, err
		}

		rhelv2Layer.CPEs = cpes

		layers = append(layers, &rhelv2Layer)
	}
	if err := rows.Err(); err != nil {
		utils.IgnoreError(tx.Rollback)
		return nil, err
	}

	for _, layer := range layers {
		if err := pgSQL.getPackagesByLayer(tx, layer); err != nil {
			utils.IgnoreError(tx.Rollback)
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		utils.IgnoreError(tx.Rollback)
		return nil, handleError("GetRHELv2Layers.Commit()", err)
	}

	// layers is in order from highest layer to lowest.
	// This may be counterintuitive, so reverse it.
	for left, right := 0, len(layers)-1; left < right; left, right = left+1, right-1 {
		layers[left], layers[right] = layers[right], layers[left]
	}

	return layers, nil
}

func (pgSQL *pgSQL) getPackagesByLayer(tx *sql.Tx, layer *database.RHELv2Layer) error {
	rows, err := tx.Query(searchRHELv2Package, layer.Hash)
	if err != nil {
		return err
	}
	defer utils.IgnoreError(rows.Close)

	for rows.Next() {
		var pkg database.RHELv2Package
		err := rows.Scan(
			&pkg.ID,
			&pkg.Name,
			&pkg.Version,
			&pkg.Module,
			&pkg.Arch,
		)
		if err != nil {
			return err
		}

		layer.Pkgs = append(layer.Pkgs, &pkg)
	}

	return rows.Err()
}

func (pgSQL *pgSQL) FindRHELv2Layer(name string) (database.Layer, error) {
	row := pgSQL.QueryRow(searchRHELv2Layer, name)
	var hash, dist string
	err := row.Scan(&hash, &dist)
	if err == sql.ErrNoRows {
		return database.Layer{}, commonerr.ErrNotFound
	}
	if err != nil {
		return database.Layer{}, errors.Wrapf(err, "searching for RHELv2 layer %s", name)
	}

	return database.Layer{
		Name:      hash,
		Namespace: &database.Namespace{Name: dist},
	}, nil
}
