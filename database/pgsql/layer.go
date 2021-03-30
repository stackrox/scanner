// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgsql

import (
	"database/sql"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/utils"
	"strconv"
	"strings"
	"time"

	"github.com/guregu/null/zero"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/features"
)

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
	subquery := "all"
	if withFeatures {
		subquery += "/features"
	} else if withVulnerabilities {
		subquery += "/features+vulnerabilities"
	}
	defer observeQueryTime("FindLayer", subquery, time.Now())

	// Find the layer
	var (
		layer           database.Layer
		parentID        zero.Int
		parentName      zero.String
		nsID            zero.Int
		nsName          sql.NullString
		nsVersionFormat sql.NullString
	)

	t := time.Now()
	err := pgSQL.QueryRow(searchLayer, name).Scan(
		&layer.ID,
		&layer.Name,
		&layer.EngineVersion,
		&parentID,
		&parentName,
		&nsID,
		&nsName,
		&nsVersionFormat,
	)
	observeQueryTime("FindLayer", "searchLayer", t)

	if err != nil {
		return layer, handleError("searchLayer", err)
	}

	if !parentID.IsZero() {
		layer.Parent = &database.Layer{
			Model: database.Model{ID: int(parentID.Int64)},
			Name:  parentName.String,
		}
	}
	if !nsID.IsZero() {
		layer.Namespace = &database.Namespace{
			Model:         database.Model{ID: int(nsID.Int64)},
			Name:          nsName.String,
			VersionFormat: nsVersionFormat.String,
		}
	}

	// Find its features
	if withFeatures || withVulnerabilities {
		// Create a transaction to disable hash/merge joins as our experiments have shown that
		// PostgreSQL 9.4 makes bad planning decisions about:
		// - joining the layer tree to feature versions and feature
		// - joining the feature versions to affected/fixed feature version and vulnerabilities
		// It would for instance do a merge join between affected feature versions (300 rows, estimated
		// 3000 rows) and fixed in feature version (100k rows). In this case, it is much more
		// preferred to use a nested loop.
		tx, err := pgSQL.Begin()
		if err != nil {
			return layer, handleError("FindLayer.Begin()", err)
		}
		defer tx.Commit()

		_, err = tx.Exec(disableHashJoin)
		if err != nil {
			log.WithError(err).Warningf("FindLayer: could not disable hash join")
		}
		_, err = tx.Exec(disableMergeJoin)
		if err != nil {
			log.WithError(err).Warningf("FindLayer: could not disable merge join")
		}

		t = time.Now()
		featureVersions, err := getLayerFeatureVersions(tx, layer.ID)
		observeQueryTime("FindLayer", "getLayerFeatureVersions", t)

		if err != nil {
			return layer, err
		}

		layer.Features = featureVersions

		if withVulnerabilities {
			// Load the vulnerabilities that affect the FeatureVersions.
			t = time.Now()
			err := loadAffectedBy(tx, layer.Features)
			observeQueryTime("FindLayer", "loadAffectedBy", t)

			if err != nil {
				return layer, err
			}
		}
	}

	return layer, nil
}

// getLayerFeatureVersions returns list of database.FeatureVersion that a database.Layer has.
func getLayerFeatureVersions(tx *sql.Tx, layerID int) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	// Query.
	rows, err := tx.Query(searchLayerFeatureVersion, layerID)
	if err != nil {
		return featureVersions, handleError("searchLayerFeatureVersion", err)
	}
	defer rows.Close()

	// Scan query.
	var modification string
	mapFeatureVersions := make(map[int]database.FeatureVersion)
	for rows.Next() {
		var fv database.FeatureVersion
		err = rows.Scan(
			&fv.ID,
			&modification,
			&fv.Feature.Namespace.ID,
			&fv.Feature.Namespace.Name,
			&fv.Feature.Namespace.VersionFormat,
			&fv.Feature.ID,
			&fv.Feature.Name,
			&fv.ID,
			&fv.Version,
			&fv.AddedBy.ID,
			&fv.AddedBy.Name,
		)
		if err != nil {
			return featureVersions, handleError("searchLayerFeatureVersion.Scan()", err)
		}

		// Do transitive closure.
		switch modification {
		case "add":
			mapFeatureVersions[fv.ID] = fv
		case "del":
			delete(mapFeatureVersions, fv.ID)
		default:
			log.WithField("modification", modification).Warning("unknown Layer_diff_FeatureVersion's modification")
			return featureVersions, database.ErrInconsistent
		}
	}
	if err = rows.Err(); err != nil {
		return featureVersions, handleError("searchLayerFeatureVersion.Rows()", err)
	}

	// Build result by converting our map to a slice.
	for _, featureVersion := range mapFeatureVersions {
		featureVersions = append(featureVersions, featureVersion)
	}

	return featureVersions, nil
}

// loadAffectedBy returns the list of database.Vulnerability that affect the given
// FeatureVersion.
func loadAffectedBy(tx *sql.Tx, featureVersions []database.FeatureVersion) error {
	if len(featureVersions) == 0 {
		return nil
	}

	// Construct list of FeatureVersion IDs, we will do a single query
	featureVersionIDs := make([]int, 0, len(featureVersions))
	for i := 0; i < len(featureVersions); i++ {
		featureVersionIDs = append(featureVersionIDs, featureVersions[i].ID)
	}

	rows, err := tx.Query(searchFeatureVersionVulnerability,
		buildInputArray(featureVersionIDs))
	if err != nil && err != sql.ErrNoRows {
		return handleError("searchFeatureVersionVulnerability", err)
	}
	defer rows.Close()

	vulnerabilities := make(map[int][]database.Vulnerability, len(featureVersions))
	var featureversionID int
	for rows.Next() {
		var vulnerability database.Vulnerability
		err := rows.Scan(
			&featureversionID,
			&vulnerability.ID,
			&vulnerability.Name,
			&vulnerability.Description,
			&vulnerability.Link,
			&vulnerability.Severity,
			&vulnerability.Metadata,
			&vulnerability.Namespace.Name,
			&vulnerability.Namespace.VersionFormat,
			&vulnerability.FixedBy,
		)
		if err != nil {
			return handleError("searchFeatureVersionVulnerability.Scan()", err)
		}
		vulnerabilities[featureversionID] = append(vulnerabilities[featureversionID], vulnerability)
	}
	if err = rows.Err(); err != nil {
		return handleError("searchFeatureVersionVulnerability.Rows()", err)
	}

	// Assign vulnerabilities to every FeatureVersions
	for i := 0; i < len(featureVersions); i++ {
		featureVersions[i].AffectedBy = vulnerabilities[featureVersions[i].ID]
	}

	return nil
}

// Internally, only Feature additions/removals are stored for each layer. If a layer has a parent,
// the Feature list will be compared to the parent's Feature list and the difference will be stored.
// Note that when the Namespace of a layer differs from its parent, it is expected that several
// Feature that were already included a parent will have their Namespace updated as well
// (happens when Feature detectors relies on the detected layer Namespace). However, if the listed
// Feature has the same Name/Version as its parent, InsertLayer considers that the Feature hasn't
// been modified.
func (pgSQL *pgSQL) InsertLayer(layer database.Layer) error {
	tf := time.Now()

	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return commonerr.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, true, false)
	if err != nil && err != commonerr.ErrNotFound {
		return err
	} else if err == nil {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine version, do nothing.
			return commonerr.ErrNoNeedToInsert
		}

		layer.ID = existingLayer.ID
	}

	// We do `defer observeQueryTime` here because we don't want to observe existing layers.
	defer observeQueryTime("InsertLayer", "all", tf)

	// Get parent ID.
	var parentID zero.Int
	if layer.Parent != nil {
		if layer.Parent.ID == 0 {
			log.Warning("Parent is expected to be retrieved from database when inserting a layer.")
			return commonerr.NewBadRequestError("Parent is expected to be retrieved from database when inserting a layer.")
		}

		parentID = zero.IntFrom(int64(layer.Parent.ID))
	}

	// Find or insert namespace if provided.
	var namespaceID zero.Int
	if layer.Namespace != nil {
		n, err := pgSQL.insertNamespace(*layer.Namespace)
		if err != nil {
			return err
		}
		namespaceID = zero.IntFrom(int64(n))
	} else if layer.Namespace == nil && layer.Parent != nil {
		// Import the Namespace from the parent if it has one and this layer doesn't specify one.
		if layer.Parent.Namespace != nil {
			namespaceID = zero.IntFrom(int64(layer.Parent.Namespace.ID))
		}
	}

	return pgSQL.insertLayerTx(&layer, namespaceID, parentID)
}

func (pgSQL *pgSQL) insertLayerTx(layer *database.Layer, namespaceID, parentID zero.Int) error {
	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		return handleError("InsertLayer.Begin()", err)
	}

	if layer.ID == 0 {
		// Insert a new layer.
		err = tx.QueryRow(insertLayer, layer.Name, layer.EngineVersion, parentID, namespaceID).
			Scan(&layer.ID)
		if err != nil {
			tx.Rollback()

			if err == sql.ErrNoRows {
				// Ignore this error, another process collided.
				log.Debug("Attempted to insert duplicate layer.")
				return nil
			}
			return handleError("insertLayer", err)
		}
	} else {
		// Update an existing layer.
		_, err = tx.Exec(updateLayer, layer.ID, layer.EngineVersion, namespaceID)
		if err != nil {
			tx.Rollback()
			return handleError("updateLayer", err)
		}

		// Remove all existing Layer_diff_FeatureVersion.
		_, err = tx.Exec(removeLayerDiffFeatureVersion, layer.ID)
		if err != nil {
			tx.Rollback()
			return handleError("removeLayerDiffFeatureVersion", err)
		}
	}

	if !features.ContinueUnknownOS.Enabled() || layer.Namespace != nil {
		// Update Layer_diff_FeatureVersion now.
		err = pgSQL.updateDiffFeatureVersions(tx, layer)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit transaction.
	if err = tx.Commit(); err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Commit()", err)
	}

	return nil
}

func (pgSQL *pgSQL) updateDiffFeatureVersions(tx *sql.Tx, layer *database.Layer) error {
	// add and del are the FeatureVersion diff we should insert.
	var add []database.FeatureVersion
	var del []database.FeatureVersion

	if layer.Parent == nil {
		// There is no parent, every Features are added.
		add = append(add, layer.Features...)
	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

		// Build name:version structures.
		layerFeaturesMapNV, layerFeaturesNV := createNV(layer.Features)
		parentLayerFeaturesMapNV, parentLayerFeaturesNV := createNV(layer.Parent.Features)

		// Calculate the added and deleted FeatureVersions name:version.
		addNV := compareStringLists(layerFeaturesNV, parentLayerFeaturesNV)
		delNV := compareStringLists(parentLayerFeaturesNV, layerFeaturesNV)

		// Fill the structures containing the added and deleted FeatureVersions.
		for _, nv := range addNV {
			add = append(add, *layerFeaturesMapNV[nv])
		}
		for _, nv := range delNV {
			del = append(del, *parentLayerFeaturesMapNV[nv])
		}
	}

	// Insert FeatureVersions in the database.
	addIDs, err := pgSQL.insertFeatureVersions(add)
	if err != nil {
		return err
	}
	delIDs, err := pgSQL.insertFeatureVersions(del)
	if err != nil {
		return err
	}

	// Insert diff in the database.
	if len(addIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "add", buildInputArray(addIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Add", err)
		}
	}
	if len(delIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "del", buildInputArray(delIDs))
		if err != nil {
			parentID := "no_parent"
			if layer.Parent != nil {
				parentID = strconv.Itoa(layer.Parent.ID)
			}
			// TODO: Figure out why this error is hit. Priceline is hitting it but we cannot reproduce it.
			log.WithError(err).Warnf("Failed to insert layer diff feature version.Del. layerID: %d, parent layer ID: %s, addIDs: %+v; delIDs: %+v, add: %+v, del: %+v", layer.ID, parentID, addIDs, delIDs, add, del)
		}
	}

	return nil
}

func createNV(features []database.FeatureVersion) (map[string]*database.FeatureVersion, []string) {
	mapNV := make(map[string]*database.FeatureVersion)
	sliceNV := make([]string, 0, len(features))

	for i := 0; i < len(features); i++ {
		fv := &features[i]
		nv := strings.Join([]string{fv.Feature.Namespace.Name, fv.Feature.Name, fv.Version}, ":")
		mapNV[nv] = fv
		sliceNV = append(sliceNV, nv)
	}

	return mapNV, sliceNV
}

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

	dist := layer.Dist.DID + ":" + layer.Dist.VersionID
	_, err := tx.Exec(insertLayer, layer.Hash, layer.ParentHash, dist, layer.CPEs)
	return err
}

func (pgSQL *pgSQL) insertRHELv2Packages(tx *sql.Tx, layer string, pkgs []*database.Package) error {
	const (
		insert = ` 
		INSERT INTO package (name, kind, version, module, arch)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (name, kind, version, module, arch) DO NOTHING;
		`

		insertWith = `
		WITH source_package AS (
			SELECT id AS source_id
			FROM package
			WHERE name = $1
			  AND kind = $2
			  AND version = $3
			  AND module = $4
			  AND arch = $5
		),
		binary_package AS (
			SELECT id AS package_id
			FROM package
			WHERE name = $6
			  AND kind = $7
			  AND version = $8
			  AND module = $9
			  AND arch = $10
		),
		layer AS (
			SELECT id AS layer_id
			FROM rhelv2_layer
			WHERE rhelv2_layer.hash = $11
		)
		INSERT
		INTO package_scanartifact (layer_id, package_id, source_id)
		VALUES ((SELECT layer_id FROM layer),
				(SELECT package_id FROM binary_package),
				(SELECT source_id FROM source_package))
		ON CONFLICT DO NOTHING;
		`
	)

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insert, pkg.Name, pkg.Kind, pkg.Version, pkg.Module, pkg.Arch)
		if err != nil {
			return err
		}

		if pkg.Source == nil {
			// Insert empty source package so the following query does not fail.
			pkg.Source = new(database.Package)
		}
		source := pkg.Source
		_, err = tx.Exec(insert, source.Name, source.Kind, source.Version, source.Module, source.Arch)
		if err != nil {
			return err
		}
	}

	for _, pkg := range pkgs {
		if pkg.Name == "" {
			continue
		}

		_, err := tx.Exec(insertWith,
			pkg.Source.Name,
			pkg.Source.Kind,
			pkg.Source.Version,
			pkg.Source.Module,
			pkg.Source.Arch,
			pkg.Name,
			pkg.Kind,
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
		return nil, handleError("InsertRHELv2Layer.Begin()", err)
	}

	rows, err := tx.Query(query, layerHash)
	if err != nil {
		return nil, err
	}
	defer utils.IgnoreError(rows.Close)

	var layers []*database.RHELv2Layer

	for rows.Next() {
		var rhelv2Layer database.RHELv2Layer
		var dist string
		if err := rows.Scan(&rhelv2Layer.ID, &rhelv2Layer.Hash, &dist, &rhelv2Layer.CPEs); err != nil {
			utils.IgnoreError(tx.Rollback)
			return nil, err
		}

		name, version := stringutils.Split2(dist, ":")
		rhelv2Layer.Dist.DID = name
		rhelv2Layer.Dist.VersionID = version

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
			package.kind,
			package.version,
			package.module,
			package.arch,
			source_package.id,
			source_package.name,
			source_package.kind,
			source_package.version,
			source_package.module,
			source_package.arch
		FROM
			package_scanartifact
			LEFT JOIN package ON
					package_scanartifact.package_id = package.id
			LEFT JOIN package AS source_package ON
					package_scanartifact.source_id = source_package.id
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
		var pkg, srcPkg database.Package
		err := rows.Scan(
			&pkg.ID,
			&pkg.Name,
			&pkg.Kind,
			&pkg.Version,
			&pkg.Module,
			&pkg.Arch,
			&srcPkg.ID,
			&srcPkg.Name,
			&srcPkg.Kind,
			&srcPkg.Version,
			&srcPkg.Module,
			&srcPkg.Arch,
		)
		if err != nil {
			return err
		}

		pkg.Source = &srcPkg
		layer.Pkgs = append(layer.Pkgs, &pkg)
	}

	return rows.Err()
}
