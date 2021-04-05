// +build db_integration

package pgsql

import (
	"github.com/stackrox/scanner/database"
	"testing"
)

func TestInsertRHELv2Layer(t *testing.T) {
	datastore, err := openDatabaseForTest("InsertRHELv2Layer", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	layer := &database.RHELv2Layer{
		Hash:       "sha256:howdy",
		ParentHash: "sha256:pardner",
		Dist:       "rhel:8",
		Pkgs:       nil,
		CPEs:       nil,
	}


}
