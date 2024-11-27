///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package pgsql

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/lib/pq"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/database/metrics"
)

func (pgSQL *pgSQL) InsertRHELv2Layer(layer *database.RHELv2Layer) error {
	defer metrics.ObserveQueryTime("insertRHELv2Layer", "all", time.Now())

	tx, err := pgSQL.Begin()
	if err != nil {
		return handleError("InsertRHELv2Layer.Begin()", err)
	}

	if err := pgSQL.insertRHELv2Layer(tx, layer); err != nil {
		utils.IgnoreError(tx.Rollback)
		return err
	}

	if err := pgSQL.insertRHELv2Packages(tx, layer.Hash, layer.Pkgs, layer.Lineage); err != nil {
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
	defer metrics.ObserveQueryTime("insertRHELv2Layer", "layer", time.Now())

	_, err := tx.Exec(insertRHELv2Layer, layer.Hash, layer.ParentHash, layer.Dist, pq.Array(layer.CPEs), layer.Lineage, layer.ParentLineage)
	return err
}

func (pgSQL *pgSQL) insertRHELv2Packages(tx *sql.Tx, layer string, pkgs []*database.RHELv2Package, lineage string) error {
	// Sort packages to avoid potential deadlock.
	// Sort by the unique index (name, version, module, arch).
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.Arch < b.Arch
	})

	defer metrics.ObserveQueryTime("insertRHELv2Layer", "packages", time.Now())

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insertRHELv2Package, pkg.Name, pkg.Version, pkg.Module, pkg.Arch, pkg.ExecutableToDependencies, pkg.LibraryToDependencies)
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
			lineage,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (pgSQL *pgSQL) GetRHELv2Layers(layerHash, layerLineage string) ([]*database.RHELv2Layer, error) {
	defer metrics.ObserveQueryTime("getRHELv2Layers", "all", time.Now())

	tx, err := pgSQL.BeginTx(context.Background(), &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, handleError("GetRHELv2Layers.Begin()", err)
	}

	rows, err := tx.Query(searchRHELv2Layers, layerHash, layerLineage)
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
		if err := rows.Scan(&rhelv2Layer.ID, &rhelv2Layer.Hash, &rhelv2Layer.Dist, pq.Array(&cpes), &rhelv2Layer.Lineage); err != nil {
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

	if err := pgSQL.populatePackages(tx, layers); err != nil {
		utils.IgnoreError(tx.Rollback)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		utils.IgnoreError(tx.Rollback)
		return nil, handleError("GetRHELv2Layers.Commit()", err)
	}

	// layers is in order from the highest layer to lowest.
	// This may be counterintuitive, so reverse it.
	for left, right := 0, len(layers)-1; left < right; left, right = left+1, right-1 {
		layers[left], layers[right] = layers[right], layers[left]
	}

	return layers, nil
}

// populatePackages populates the packages for each layer.
// Upon error, the transaction is NOT rolled back. That is up to the caller.
func (pgSQL *pgSQL) populatePackages(tx *sql.Tx, layers []*database.RHELv2Layer) error {
	defer metrics.ObserveQueryTime("getRHELv2Layers", "packages", time.Now())

	for _, layer := range layers {
		if err := pgSQL.getPackagesByLayer(tx, layer); err != nil {
			return err
		}
	}

	return nil
}

// getPackagesByLayer retrieves the packages for the given layer.
// Upon error, the transaction is NOT rolled back. That is up to the caller.
func (pgSQL *pgSQL) getPackagesByLayer(tx *sql.Tx, layer *database.RHELv2Layer) error {
	defer metrics.ObserveQueryTime("getRHELv2Layers", "packagesByLayer", time.Now())

	rows, err := tx.Query(searchRHELv2Package, layer.Hash, layer.Lineage)
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
			&pkg.ExecutableToDependencies,
			&pkg.LibraryToDependencies,
		)
		if err != nil {
			return err
		}

		layer.Pkgs = append(layer.Pkgs, &pkg)
	}

	return rows.Err()
}
