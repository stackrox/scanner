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
	"time"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/database/metrics"
	"github.com/stackrox/scanner/pkg/commonerr"
)

func (pgSQL *pgSQL) insertNamespace(namespace database.Namespace) (int, error) {
	if namespace.Name == "" {
		return 0, commonerr.NewBadRequestError("could not find/insert invalid Namespace")
	}

	// We do `defer metrics.ObserveQueryTime` here because we don't want to observe cached namespaces.
	defer metrics.ObserveQueryTime("insertNamespace", "all", time.Now())

	var id int
	err := pgSQL.QueryRow(insertNamespace, namespace.Name, namespace.VersionFormat).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("insertNamespace", err)
	}
	if err == sql.ErrNoRows {
		// Query Namespace for the ID because it already exists.
		err := pgSQL.QueryRow(searchNamespace, namespace.Name).Scan(&id)
		if err != nil {
			return 0, handleError("searchNamespace", err)
		}
		if id == 0 {
			return 0, handleError("searchNamespace", commonerr.ErrNotFound)
		}
	}

	return id, nil
}
