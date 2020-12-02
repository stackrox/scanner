// Copyright 2015 clair authors
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

import "strconv"

const (
	lockVulnerabilityAffects = `LOCK Vulnerability_Affects_FeatureVersion IN SHARE ROW EXCLUSIVE MODE`
	disableHashJoin          = `SET LOCAL enable_hashjoin = off`
	disableMergeJoin         = `SET LOCAL enable_mergejoin = off`

	// keyvalue.go
	upsertKeyValue = `
		INSERT INTO KeyValue(key, value)
		VALUES($1, $2)
		ON CONFLICT (key)
		DO UPDATE SET value = $2
	`
	searchKeyValue = `SELECT value FROM KeyValue WHERE key = $1`

	// namespace.go
	insertNamespace = `
		INSERT INTO Namespace(name, version_format)
		VALUES($1, $2)
		ON CONFLICT (name)
		DO NOTHING
		RETURNING id
	`

	searchNamespace = `SELECT id FROM Namespace WHERE name = $1`

	// feature.go
	insertFeature = `
		INSERT INTO Feature(name, namespace_id)
		VALUES($1, $2)
		ON CONFLICT (name, namespace_id)
		DO NOTHING
		RETURNING id
	`

	searchFeature = `SELECT id FROM Feature WHERE name = $1 AND namespace_id = $2`

	searchFeatureVersion = `
		SELECT id FROM FeatureVersion WHERE feature_id = $1 AND version = $2`

	insertFeatureVersion = `
		INSERT INTO FeatureVersion(feature_id, version)
		VALUES($1, $2)
		ON CONFLICT (feature_id, version)
		DO NOTHING
		RETURNING id
	`

	searchVulnerabilityFixedInFeature = `
		SELECT id, vulnerability_id, version FROM Vulnerability_FixedIn_Feature
    WHERE feature_id = $1`

	insertVulnerabilityAffectsFeatureVersion = `
		INSERT INTO Vulnerability_Affects_FeatureVersion(vulnerability_id, featureversion_id, fixedin_id)
		VALUES($1, $2, $3)`

	// layer.go
	searchLayer = `
		SELECT l.id, l.name, l.engineversion, p.id, p.name, n.id, n.name, n.version_format
		FROM Layer l
			LEFT JOIN Layer p ON l.parent_id = p.id
			LEFT JOIN Namespace n ON l.namespace_id = n.id
		WHERE l.name = $1;`

	searchLayerFeatureVersion = `
		WITH RECURSIVE layer_tree(id, name, parent_id, depth, path, cycle) AS(
			SELECT l.id, l.name, l.parent_id, 1, ARRAY[l.id], false
			FROM Layer l
			WHERE l.id = $1
		UNION ALL
			SELECT l.id, l.name, l.parent_id, lt.depth + 1, path || l.id, l.id = ANY(path)
			FROM Layer l, layer_tree lt
			WHERE l.id = lt.parent_id
		)
		SELECT ldf.featureversion_id, ldf.modification, fn.id, fn.name, fn.version_format, f.id, f.name, fv.id, fv.version, ltree.id, ltree.name
		FROM Layer_diff_FeatureVersion ldf
		JOIN (
			SELECT row_number() over (ORDER BY depth DESC), id, name FROM layer_tree
		) AS ltree (ordering, id, name) ON ldf.layer_id = ltree.id, FeatureVersion fv, Feature f, Namespace fn
		WHERE ldf.featureversion_id = fv.id AND fv.feature_id = f.id AND f.namespace_id = fn.id
		ORDER BY ltree.ordering`

	searchLanguageComponentsInImage = `
		WITH RECURSIVE layer_tree(id, name, parent_id, depth, path, cycle) AS(
			SELECT l.id, l.name, l.parent_id, 1, ARRAY[l.id], false
			FROM Layer l
			WHERE l.name = $1
		UNION ALL
			SELECT l.id, l.name, l.parent_id, lt.depth + 1, path || l.id, l.id = ANY(path)
			FROM Layer l, layer_tree lt
			WHERE l.id = lt.parent_id
		)
		SELECT ll.layer_name, ll.component_data, ll.removed_components
		FROM LanguageLayer ll
		JOIN (
			SELECT row_number() over (ORDER BY depth DESC), id, name FROM layer_tree
		) AS ltree (ordering, id, name) ON ll.layer_id = ltree.id ORDER BY ltree.ordering`

	searchFeatureVersionVulnerability = `
			SELECT vafv.featureversion_id, v.id, v.name, v.description, v.link, v.severity, v.metadata,
				vn.name, vn.version_format, vfif.version
			FROM Vulnerability_Affects_FeatureVersion vafv, Vulnerability v,
					 Namespace vn, Vulnerability_FixedIn_Feature vfif
			WHERE vafv.featureversion_id = ANY($1::integer[])
						AND vfif.vulnerability_id = v.id
						AND vafv.fixedin_id = vfif.id
						AND v.namespace_id = vn.id
						AND v.deleted_at IS NULL`

	insertLayer = `
		INSERT INTO Layer(name, engineversion, parent_id, namespace_id, created_at)
		VALUES($1, $2, $3, $4, CURRENT_TIMESTAMP)
		ON CONFLICT DO NOTHING
		RETURNING id
	`

	updateLayer = `UPDATE LAYER SET engineversion = $2, namespace_id = $3 WHERE id = $1`

	removeLayerDiffFeatureVersion = `
		DELETE FROM Layer_diff_FeatureVersion
		WHERE layer_id = $1`

	insertLayerDiffFeatureVersion = `
		INSERT INTO Layer_diff_FeatureVersion(layer_id, featureversion_id, modification)
			SELECT $1, fv.id, $2
			FROM FeatureVersion fv
			WHERE fv.id = ANY($3::integer[])`

	// vulnerability.go
	searchVulnerabilityBase = `
	  SELECT v.id, v.name, n.id, n.name, n.version_format, v.description, v.link, v.severity, v.metadata
	  FROM Vulnerability v JOIN Namespace n ON v.namespace_id = n.id`
	searchVulnerabilityForUpdate          = ` FOR UPDATE OF v`
	searchVulnerabilityByNamespaceAndName = ` WHERE n.name = $1 AND v.name = $2 AND v.deleted_at IS NULL`
	searchVulnerabilityByNamespace        = ` WHERE n.name = $1 AND v.deleted_at IS NULL
		  				  AND v.id >= $2
						  ORDER BY v.id
						  LIMIT $3`

	searchVulnerabilityFixedIn = `
		SELECT vfif.version, f.id, f.Name
		FROM Vulnerability_FixedIn_Feature vfif JOIN Feature f ON vfif.feature_id = f.id
		WHERE vfif.vulnerability_id = $1`

	insertVulnerability = `
		INSERT INTO Vulnerability(namespace_id, name, description, link, severity, metadata, created_at)
		VALUES($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
		RETURNING id`

	insertVulnerabilityFixedInFeature = `
		INSERT INTO Vulnerability_FixedIn_Feature(vulnerability_id, feature_id, version)
		VALUES($1, $2, $3)
		ON CONFLICT (vulnerability_id, feature_id)
		DO NOTHING
		RETURNING id
	`

	searchFeatureVersionByFeature = `SELECT id, version FROM FeatureVersion WHERE feature_id = $1`

	removeVulnerability = `
		UPDATE Vulnerability
    SET deleted_at = CURRENT_TIMESTAMP
    WHERE namespace_id = (SELECT id FROM Namespace WHERE name = $1)
          AND name = $2
          AND deleted_at IS NULL
    RETURNING id`

	// locks
	insertLock        = `INSERT INTO Lock(name, owner, until) VALUES($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id`
	searchLock        = `SELECT owner, until FROM Lock WHERE name = $1`
	updateLock        = `UPDATE Lock SET until = $3 WHERE name = $1 AND owner = $2`
	removeLock        = `DELETE FROM Lock WHERE name = $1 AND owner = $2`
	removeLockExpired = `DELETE FROM LOCK WHERE until < CURRENT_TIMESTAMP`
)

// buildInputArray constructs a PostgreSQL input array from the specified integers.
// Useful to use the `= ANY($1::integer[])` syntax that let us use a IN clause while using
// a single placeholder.
func buildInputArray(ints []int) string {
	str := "{"
	for i := 0; i < len(ints)-1; i++ {
		str = str + strconv.Itoa(ints[i]) + ","
	}
	str = str + strconv.Itoa(ints[len(ints)-1]) + "}"
	return str
}
