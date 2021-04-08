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

func (pgSQL *pgSQL) GetRHELv2Layers(layerHash string) ([]*database.RHELv2Layer, error) {
	// Inside the `WITH RECURSIVE`, the base case is the top query, and the
	// recursive case is the bottom query.
	// Base: find the layer by hash.
	// Recursive: find the layer whose hash matches the current layer's parent hash
	//
	// This query looks for all the layers in the given layer's hierarchy.
	const (
		query = `
		WITH RECURSIVE layers AS (
			SELECT id, hash, parent_hash, dist, cpes
			FROM rhelv2_layer
			WHERE hash = $1
			UNION
				SELECT l.id, l.hash, l.parent_hash, l.dist, l.cpes
				FROM layers ll, rhelv2_layer l
				WHERE ll.parent_hash = l.hash
		)
		SELECT id, hash, dist, cpes
		FROM layers;
		`
	)

	tx, err := pgSQL.Begin()
	if err != nil {
		return nil, handleError("GetRHELv2Layers.Begin()", err)
	}

	rows, err := tx.Query(query, layerHash)
	if err != nil {
		return nil, err
	}
	defer utils.IgnoreError(rows.Close)

	var layers []*database.RHELv2Layer

	for rows.Next() {
		var rhelv2Layer database.RHELv2Layer
		if err := rows.Scan(&rhelv2Layer.ID, &rhelv2Layer.Hash, &rhelv2Layer.Dist, &rhelv2Layer.CPEs); err != nil {
			utils.IgnoreError(tx.Rollback)
			return nil, err
		}

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

	return layers, nil
}

func (pgSQL *pgSQL) getPackagesByLayer(tx *sql.Tx, layer *database.RHELv2Layer) error {
	const (
		query = `
		SELECT
			package.id,
			package.name,
			package.version,
			package.module,
			package.arch
		FROM
			package_scanartifact
			LEFT JOIN package ON
					package_scanartifact.package_id = package.id
			JOIN rhelv2_layer ON rhelv2_layer.hash = $1
		WHERE
			package_scanartifact.layer_id = rhelv2_layer.id;
		`
	)

	rows, err := tx.Query(query, layer.Hash)
	if err != nil {
		return err
	}
	defer utils.IgnoreError(rows.Close)

	for rows.Next() {
		var pkg database.Package
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
