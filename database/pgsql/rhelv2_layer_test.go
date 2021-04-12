// +build db_integration

package pgsql

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/assert"
)

func TestInsertRHELv2Layer(t *testing.T) {
	datastore, err := openDatabaseForTest("InsertRHELv2Layer", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Layer without any packages nor CPEs.
	layer := &database.RHELv2Layer{
		Hash:       "sha256:howdy",
		ParentHash: "sha256:howdyhowdy",
		Dist:       "rhel:8",
		Pkgs:       nil,
		CPEs:       nil,
	}

	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)

	// Layer with packages and CPEs.
	layer = &database.RHELv2Layer{
		Hash:       "sha256:hellothere",
		ParentHash: "sha256:generalkenobi",
		Dist:       "rhel:7",
		Pkgs: []*database.RHELv2Package{
			{
				Name:    "pkg",
				Version: "v1",
				Arch:    "x86_64",
			},
			{
				Name:    "pkg2",
				Version: "v2",
				Module:  "module",
				Arch:    "i686",
			},
		},
		CPEs: []string{"cpe", "cpe2"},
	}

	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)

	// Layer without a parent.
	layer = &database.RHELv2Layer{
		Hash: "sha256:hi",
		Dist: "rhel:6",
		Pkgs: []*database.RHELv2Package{
			{
				Name:    "pkg",
				Version: "v1",
				Arch:    "x86_64",
			},
			{
				Name:    "pkg2",
				Version: "v2",
				Module:  "module",
				Arch:    "i686",
			},
		},
		CPEs: []string{"cpe", "cpe2"},
	}

	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)
}
