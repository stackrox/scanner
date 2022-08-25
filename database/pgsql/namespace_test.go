//go:build db_integration || slim_db_integration
// +build db_integration slim_db_integration

// Copyright 2016 clair authors
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
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stretchr/testify/assert"
)

func TestInsertNamespace(t *testing.T) {
	datastore, err := openDatabaseForTest("InsertNamespace", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Invalid Namespace.
	id0, err := datastore.insertNamespace(database.Namespace{})
	assert.NotNil(t, err)
	assert.Zero(t, id0)

	// Insert Namespace and ensure we can find it.
	id1, err := datastore.insertNamespace(database.Namespace{
		Name:          "TestInsertNamespace1",
		VersionFormat: dpkg.ParserName,
	})
	assert.Nil(t, err)
	id2, err := datastore.insertNamespace(database.Namespace{
		Name:          "TestInsertNamespace1",
		VersionFormat: dpkg.ParserName,
	})
	assert.Nil(t, err)
	assert.Equal(t, id1, id2)
}
