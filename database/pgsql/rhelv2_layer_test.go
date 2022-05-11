// +build db_integration
// +build slim_db_integration

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

func TestGetRHELv2Layers(t *testing.T) {
	datastore, err := openDatabaseForTest("GetRHELv2Layers", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// base layer
	layer := &database.RHELv2Layer{
		Hash: "sha256:howdy",
		Dist: "rhel:8",
	}

	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)

	layer1Pkgs := []*database.RHELv2Package{
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
	}
	layer1CPEs := []string{"cpe", "cpe2"}

	// child layer.
	layer = &database.RHELv2Layer{
		Hash:       "sha256:howdyhowdy",
		ParentHash: "sha256:howdy",
		Dist:       "rhel:8",
		Pkgs:       layer1Pkgs,
		CPEs:       layer1CPEs,
	}

	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)

	// Get parent layer.
	layers, err := datastore.GetRHELv2Layers("sha256:howdy")
	assert.NoError(t, err)
	assert.Len(t, layers, 1)
	layer = layers[0]
	assert.Equal(t, "sha256:howdy", layer.Hash)
	assert.Empty(t, layer.Pkgs)
	assert.Empty(t, layer.CPEs)

	// Get 2 layered-image.
	layers, err = datastore.GetRHELv2Layers("sha256:howdyhowdy")
	assert.NoError(t, err)
	assert.Len(t, layers, 2)
	layer = layers[1]
	assert.Equal(t, "sha256:howdyhowdy", layer.Hash)
	for _, pkg := range layer.Pkgs {
		pkg.ID = 0
	}
	assert.Equal(t, layer1Pkgs, layer.Pkgs)
	assert.Equal(t, layer1CPEs, layer.CPEs)
	layer = layers[0]
	assert.Equal(t, "sha256:howdy", layer.Hash)
	assert.Empty(t, layer.Pkgs)
	assert.Empty(t, layer.CPEs)

	layer2Pkgs := []*database.RHELv2Package{
		{
			Name:    "pkg",
			Version: "v1",
			Arch:    "x86_64",
		},
		{
			Name:    "pkg3",
			Version: "v3",
			Module:  "module",
			Arch:    "i686",
		},
	}

	layer2CPEs := []string{"cpe3"}

	layer = &database.RHELv2Layer{
		Hash:       "sha256:howdyhowdyhowdy",
		ParentHash: "sha256:howdyhowdy",
		Dist:       "rhel:8",
		Pkgs:       layer2Pkgs,
		CPEs:       layer2CPEs,
	}

	// Add 3rd layer to image.
	err = datastore.InsertRHELv2Layer(layer)
	assert.NoError(t, err)

	// Get 3 layered-image.
	layers, err = datastore.GetRHELv2Layers("sha256:howdyhowdyhowdy")
	assert.NoError(t, err)
	assert.Len(t, layers, 3)
	layer = layers[2]
	assert.Equal(t, "sha256:howdyhowdyhowdy", layer.Hash)
	for _, pkg := range layer.Pkgs {
		pkg.ID = 0
	}
	assert.Equal(t, layer2Pkgs, layer.Pkgs)
	assert.Equal(t, layer2CPEs, layer.CPEs)
	layer = layers[1]
	assert.Equal(t, "sha256:howdyhowdy", layer.Hash)
	for _, pkg := range layer.Pkgs {
		pkg.ID = 0
	}
	assert.Equal(t, layer1Pkgs, layer.Pkgs)
	assert.Equal(t, layer1CPEs, layer.CPEs)
	layer = layers[0]
	assert.Equal(t, "sha256:howdy", layer.Hash)
	assert.Empty(t, layer.Pkgs)
	assert.Empty(t, layer.CPEs)
}
