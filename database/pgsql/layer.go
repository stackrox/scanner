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
	"strconv"
	"time"

	"github.com/guregu/null/zero"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/database/metrics"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/rhel"
)

func (pgSQL *pgSQL) FindLayer(name string, lineage string, opts *database.DatastoreOptions) (database.Layer, error) {
	withFeatures := opts.GetWithFeatures()
	withVulnerabilities := opts.GetWithVulnerabilities()
	uncertifiedRHEL := opts.GetUncertifiedRHEL()

	subquery := "all"
	if withFeatures {
		subquery += "/features"
	} else if withVulnerabilities {
		subquery += "/features+vulnerabilities"
	}
	defer metrics.ObserveQueryTime("FindLayer", subquery, time.Now())

	// Find the layer
	var (
		layer           database.Layer
		parentID        zero.Int
		parentName      zero.String
		nsID            zero.Int
		nsName          sql.NullString
		nsVersionFormat sql.NullString
	)

	if uncertifiedRHEL {
		name = rhel.GetUncertifiedLayerName(name)
	}

	t := time.Now()
	err := pgSQL.QueryRow(searchLayer, name, lineage).Scan(
		&layer.ID,
		&layer.Name,
		&layer.EngineVersion,
		&layer.Distroless,
		&parentID,
		&parentName,
		&nsID,
		&nsName,
		&nsVersionFormat,
	)
	metrics.ObserveQueryTime("FindLayer", "searchLayer", t)

	if uncertifiedRHEL {
		layer.Name = rhel.GetOriginalLayerName(layer.Name)
	}

	if err != nil {
		return layer, handleError("searchLayer", err)
	}

	if !parentID.IsZero() {
		if uncertifiedRHEL {
			parentName.String = rhel.GetOriginalLayerName(parentName.String)
		}
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
		featureVersions, err := getLayerFeatureVersions(tx, layer.ID, lineage)
		metrics.ObserveQueryTime("FindLayer", "getLayerFeatureVersions", t)

		if err != nil {
			return layer, err
		}

		layer.Features = featureVersions

		if withVulnerabilities {
			// Load the vulnerabilities that affect the FeatureVersions.
			t = time.Now()
			err := loadAffectedBy(tx, layer.Features)
			metrics.ObserveQueryTime("FindLayer", "loadAffectedBy", t)

			if err != nil {
				return layer, err
			}
		}
	}

	return layer, nil
}

// getLayerFeatureVersions returns list of database.FeatureVersion that a database.Layer has.
func getLayerFeatureVersions(tx *sql.Tx, layerID int, lineage string) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	// Query.
	rows, err := tx.Query(searchLayerFeatureVersion, layerID, lineage)
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
			&fv.ExecutableToDependencies,
			&fv.LibraryToDependencies,
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
	var featureVersionID int
	for rows.Next() {
		var vulnerability database.Vulnerability
		err := rows.Scan(
			&featureVersionID,
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
		vulnerabilities[featureVersionID] = append(vulnerabilities[featureVersionID], vulnerability)
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
func (pgSQL *pgSQL) InsertLayer(layer database.Layer, lineage string, opts *database.DatastoreOptions) error {
	tf := time.Now()

	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return commonerr.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, lineage, &database.DatastoreOptions{
		WithFeatures:    true,
		UncertifiedRHEL: opts.GetUncertifiedRHEL(),
	})
	if err != nil && err != commonerr.ErrNotFound {
		return err
	} else if err == nil {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine version, do nothing.
			return commonerr.ErrNoNeedToInsert
		}

		layer.ID = existingLayer.ID
	}

	// We do `defer metrics.ObserveQueryTime` here because we don't want to observe existing layers.
	defer metrics.ObserveQueryTime("InsertLayer", "all", tf)

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

	if opts.GetUncertifiedRHEL() {
		layer.Name = rhel.GetUncertifiedLayerName(layer.Name)
	}

	return pgSQL.insertLayerTx(&layer, lineage, namespaceID, parentID)
}

func (pgSQL *pgSQL) insertLayerTx(layer *database.Layer, lineage string, namespaceID, parentID zero.Int) error {
	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		return handleError("InsertLayer.Begin()", err)
	}

	if layer.ID == 0 {
		// Insert a new layer.
		err = tx.QueryRow(insertLayer, layer.Name, layer.EngineVersion, lineage, parentID, namespaceID, layer.Distroless).
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
		_, err = tx.Exec(updateLayer, layer.ID, layer.EngineVersion, lineage, namespaceID, layer.Distroless)
		if err != nil {
			tx.Rollback()
			return handleError("updateLayer", err)
		}

		// Remove all existing Layer_diff_FeatureVersion.
		_, err = tx.Exec(removeLayerDiffFeatureVersion, layer.ID, lineage)
		if err != nil {
			tx.Rollback()
			return handleError("removeLayerDiffFeatureVersion", err)
		}
	}

	if !features.ContinueUnknownOS.Enabled() || layer.Namespace != nil {
		// Update Layer_diff_FeatureVersion now.
		err = pgSQL.updateDiffFeatureVersions(tx, layer, lineage)
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

type key struct {
	namespace, name, version string
}

func fvToKey(fv database.FeatureVersion) key {
	return key{
		namespace: fv.Feature.Namespace.Name,
		name:      fv.Feature.Name,
		version:   fv.Version,
	}
}

func diffFeatures(childFeatures, parentFeatures []database.FeatureVersion, distroless bool) (added, deleted []database.FeatureVersion) {
	childMap := make(map[key]database.FeatureVersion)
	for _, fv := range childFeatures {
		childMap[fvToKey(fv)] = fv
	}

	parentMap := make(map[key]database.FeatureVersion)
	for _, fv := range parentFeatures {
		parentMap[fvToKey(fv)] = fv
	}

	for key, childFV := range childMap {
		if _, ok := parentMap[key]; !ok {
			added = append(added, childFV)
		}
	}
	// Need to check for distroless because there isn't a single COW package database
	if !distroless {
		for key, parentFV := range parentMap {
			if _, ok := childMap[key]; !ok {
				deleted = append(deleted, parentFV)
			}
		}
	}
	return added, deleted
}

func (pgSQL *pgSQL) updateDiffFeatureVersions(tx *sql.Tx, layer *database.Layer, lineage string) error {
	// add and del are the FeatureVersion diff we should insert.
	var add []database.FeatureVersion
	var del []database.FeatureVersion

	if layer.Parent == nil {
		// There is no parent, every Features are added.
		add = append(add, layer.Features...)
	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

		// Calculate the added and deleted FeatureVersions name:version.
		add, del = diffFeatures(layer.Features, layer.Parent.Features, layer.Distroless)
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
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, lineage, "add", buildInputArray(addIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Add", err)
		}
	}
	if len(delIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, lineage, "del", buildInputArray(delIDs))
		if err != nil {
			parentID := "no_parent"
			if layer.Parent != nil {
				parentID = strconv.Itoa(layer.Parent.ID)
			}
			// TODO: Figure out why this error is hit.
			log.WithError(err).Warnf("Failed to insert layer diff feature version.Del. layerID: %d, parent layer ID: %s, addIDs: %+v; delIDs: %+v, add: %+v, del: %+v", layer.ID, parentID, addIDs, delIDs, add, del)
		}
	}

	return nil
}
