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
	"fmt"
	"time"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/database/metrics"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/pkg/commonerr"
)

func (pgSQL *pgSQL) insertFeature(feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, commonerr.NewBadRequestError("could not find/insert invalid Feature")
	}

	// We do `defer metrics.ObserveQueryTime` here because we don't want to observe cached features.
	defer metrics.ObserveQueryTime("insertFeature", "all", time.Now())

	// Find or create Namespace.
	namespaceID, err := pgSQL.insertNamespace(feature.Namespace)
	if err != nil {
		return 0, err
	}

	// Find or create Feature.
	var id int
	err = pgSQL.QueryRow(insertFeature, feature.Name, namespaceID).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("insertFeature", err)
	}
	if err == sql.ErrNoRows {
		// Query Feature because it already exists.
		err := pgSQL.QueryRow(searchFeature, feature.Name, namespaceID).Scan(&id)
		if err != nil {
			return 0, handleError("searchFeature", err)
		}
		if id == 0 {
			return 0, handleError("searchFeature", commonerr.ErrNotFound)
		}
	}

	return id, nil
}

func (pgSQL *pgSQL) insertFeatureVersion(fv database.FeatureVersion) (id int, err error) {
	err = versionfmt.Valid(fv.Feature.Namespace.VersionFormat, fv.Version)
	if err != nil {
		return 0, commonerr.NewBadRequestError("could not find/insert invalid FeatureVersion")
	}

	// We do `defer metrics.ObserveQueryTime` here because we don't want to observe cached featureversions.
	defer metrics.ObserveQueryTime("insertFeatureVersion", "all", time.Now())

	// Find or create Feature first.
	t := time.Now()
	featureID, err := pgSQL.insertFeature(fv.Feature)
	metrics.ObserveQueryTime("insertFeatureVersion", "insertFeature", t)

	if err != nil {
		return 0, err
	}

	fv.Feature.ID = featureID

	// Try to find the FeatureVersion.
	//
	// In a populated database, the likelihood of the FeatureVersion already being there is high.
	// If we can find it here, we then avoid using a transaction and locking the database.
	err = pgSQL.QueryRow(searchFeatureVersion, featureID, fv.Version).Scan(&fv.ID)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("searchFeatureVersion", err)
	}
	if err == nil {
		return fv.ID, nil
	}

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Begin()", err)
	}

	// Lock Vulnerability_Affects_FeatureVersion exclusively.
	// We want to prevent InsertVulnerability to modify it.
	metrics.IncLockVAFV()
	defer metrics.DecLockVAFV()
	t = time.Now()
	_, err = tx.Exec(lockVulnerabilityAffects)
	metrics.ObserveQueryTime("insertFeatureVersion", "lock", t)

	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.lockVulnerabilityAffects", err)
	}

	t = time.Now()
	err = tx.QueryRow(insertFeatureVersion,
		featureID,
		fv.Version,
		fv.ExecutableToDependencies,
		fv.LibraryToDependencies,
	).Scan(&fv.ID)
	metrics.ObserveQueryTime("insertFeatureVersion", "insertFeatureVersion", t)

	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion", err)
	}

	if err == sql.ErrNoRows {
		// Query Feature Version for id.
		// It is possible another replica inserted the feature version right before this replica attempted.
		err := pgSQL.QueryRow(searchFeatureVersion, featureID, fv.Version).Scan(&fv.ID)
		if err != nil {
			tx.Rollback()
			return 0, handleError("searchFeatureVersion", err)
		}
		if fv.ID == 0 {
			tx.Rollback()
			return 0, handleError("searchFeatureVersion", commonerr.ErrNotFound)
		}

		// The featureVersion already existed, no need to link it to
		// vulnerabilities.
		tx.Commit()

		return fv.ID, nil
	}

	// Link the new FeatureVersion with every vulnerabilities that affect it, by inserting in
	// Vulnerability_Affects_FeatureVersion.
	t = time.Now()
	err = linkFeatureVersionToVulnerabilities(tx, fv)
	metrics.ObserveQueryTime("insertFeatureVersion", "linkFeatureVersionToVulnerabilities", t)

	if err != nil {
		tx.Rollback()
		return 0, err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Commit()", err)
	}

	return fv.ID, nil
}

// TODO(Quentin-M): Batch me
func (pgSQL *pgSQL) insertFeatureVersions(featureVersions []database.FeatureVersion) ([]int, error) {
	IDs := make([]int, 0, len(featureVersions))

	for i := 0; i < len(featureVersions); i++ {
		id, err := pgSQL.insertFeatureVersion(featureVersions[i])
		if err != nil {
			return IDs, err
		}
		IDs = append(IDs, id)
	}

	return IDs, nil
}

type vulnerabilityAffectsFeatureVersion struct {
	vulnerabilityID int
	fixedInID       int
	fixedInVersion  string
}

func linkFeatureVersionToVulnerabilities(tx *sql.Tx, featureVersion database.FeatureVersion) error {
	// Select every vulnerability and the fixed version that affect this Feature.
	// TODO(Quentin-M): LIMIT
	rows, err := tx.Query(searchVulnerabilityFixedInFeature, featureVersion.Feature.ID)
	if err != nil {
		return handleError("searchVulnerabilityFixedInFeature", err)
	}
	defer rows.Close()

	var affects []vulnerabilityAffectsFeatureVersion
	for rows.Next() {
		var affect vulnerabilityAffectsFeatureVersion

		err := rows.Scan(&affect.fixedInID, &affect.vulnerabilityID, &affect.fixedInVersion)
		if err != nil {
			return handleError("searchVulnerabilityFixedInFeature.Scan()", err)
		}

		cmp, err := versionfmt.Compare(featureVersion.Feature.Namespace.VersionFormat, featureVersion.Version, affect.fixedInVersion)
		if err != nil {
			return err
		}
		if cmp < 0 {
			// The version of the FeatureVersion we are inserting is lower than the fixed version on this
			// Vulnerability, thus, this FeatureVersion is affected by it.
			affects = append(affects, affect)
		}
	}
	if err = rows.Err(); err != nil {
		return handleError("searchVulnerabilityFixedInFeature.Rows()", err)
	}
	rows.Close()

	// Insert into Vulnerability_Affects_FeatureVersion.
	for _, affect := range affects {
		// TODO(Quentin-M): Batch me.
		_, err := tx.Exec(insertVulnerabilityAffectsFeatureVersion, affect.vulnerabilityID,
			featureVersion.ID, affect.fixedInID)
		if err != nil {
			return handleError("insertVulnerabilityAffectsFeatureVersion", err)
		}
	}

	return nil
}

func (pgSQL *pgSQL) FeatureExists(namespace, feature string) (bool, error) {
	var namespaceID int
	if err := pgSQL.QueryRow(searchNamespace, namespace).Scan(&namespaceID); err != nil {
		return false, handleError("featureExists", err)
	}
	if namespaceID == 0 {
		return false, fmt.Errorf("error finding namespace %q", namespace)
	}
	var featureID int
	err := pgSQL.QueryRow(searchFeature, feature, namespaceID).Scan(&featureID)
	if err != nil && err != sql.ErrNoRows {
		return false, handleError("featureExists", err)
	}
	return featureID != 0, nil
}
