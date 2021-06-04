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

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/commonerr"
)

// InsertKeyValue stores (or updates) a single key / value tuple.
func (pgSQL *pgSQL) InsertKeyValue(key, value string) error {
	if key == "" || value == "" {
		log.Warning("could not insert a flag which has an empty name or value")
		return commonerr.NewBadRequestError("could not insert a flag which has an empty name or value")
	}

	defer observeQueryTime("InsertKeyValue", "all", time.Now())

	_, err := pgSQL.Exec(upsertKeyValue, key, value)
	if err != nil {
		return handleError("upsertKeyValue", err)
	}

	return nil
}

// GetKeyValue reads a single key / value tuple and returns an empty string if the key doesn't exist.
func (pgSQL *pgSQL) GetKeyValue(key string) (string, error) {
	defer observeQueryTime("GetKeyValue", "all", time.Now())

	var value string
	err := pgSQL.QueryRow(searchKeyValue, key).Scan(&value)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", handleError("searchKeyValue", err)
	}

	return value, nil
}
