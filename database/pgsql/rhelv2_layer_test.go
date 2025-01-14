//go:build db_integration || slim_db_integration
// +build db_integration slim_db_integration

package pgsql

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	layers, err := datastore.GetRHELv2Layers("sha256:howdy", "")
	assert.NoError(t, err)
	assert.Len(t, layers, 1)
	layer = layers[0]
	assert.Equal(t, "sha256:howdy", layer.Hash)
	assert.Empty(t, layer.Pkgs)
	assert.Empty(t, layer.CPEs)

	// Get 2 layered-image.
	layers, err = datastore.GetRHELv2Layers("sha256:howdyhowdy", "")
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
	layers, err = datastore.GetRHELv2Layers("sha256:howdyhowdyhowdy", "")
	assert.NoError(t, err)
	assert.Len(t, layers, 3)
	layer = layers[2]
	assert.Equal(t, "sha256:howdyhowdyhowdy", layer.Hash)
	resetPackageIDs(layer)
	assert.Equal(t, layer2Pkgs, layer.Pkgs)
	assert.Equal(t, layer2CPEs, layer.CPEs)
	layer = layers[1]
	assert.Equal(t, "sha256:howdyhowdy", layer.Hash)
	resetPackageIDs(layer)
	assert.Equal(t, layer1Pkgs, layer.Pkgs)
	assert.Equal(t, layer1CPEs, layer.CPEs)
	layer = layers[0]
	assert.Equal(t, "sha256:howdy", layer.Hash)
	assert.Empty(t, layer.Pkgs)
	assert.Empty(t, layer.CPEs)
}

// TestRHELv2LayerLineage verifies that data for duplicate layers with different parent
// layers (lineage) is pulled correctly.
func TestRHELv2LayerLineage(t *testing.T) {
	datastore, err := openDatabaseForTest("RHELv2LayerLineage", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Two 'fake' images will be created, each with 3 layers, the DB will resemble:
	// id |      hash       |   parent_hash   |  dist  |      cpes      |  lineage  | parent_lineage
	// ----+-----------------+-----------------+--------+----------------+-----------+----------------
	//   1 | sha256:base     |                 | rhel:8 |                |           |
	//   2 | sha256:layer1-a | sha256:base     | rhel:8 | {cpe-a,cpe2-a} | lineage   |
	//   3 | sha256:layer1-b | sha256:base     | rhel:8 | {cpe-b,cpe2-b} | lineage   |
	//   4 | sha256:leaf     | sha256:layer1-a | rhel:8 |                | lineage-a | lineage
	//   5 | sha256:leaf     | sha256:layer1-b | rhel:8 |                | lineage-b | lineage

	// base layers
	base := &database.RHELv2Layer{
		Hash: "sha256:base",
		Dist: "rhel:8",
	}

	err = datastore.InsertRHELv2Layer(base)
	require.NoError(t, err)

	layer1a := &database.RHELv2Layer{
		Hash:          "sha256:layer1-a",
		Lineage:       "lineage",
		ParentHash:    "sha256:base",
		ParentLineage: "",
		Dist:          "rhel:8",
		Pkgs: []*database.RHELv2Package{
			{Name: "pkg", Version: "v1-a", Arch: "x86_64"},
			{Name: "pkg2", Version: "v2-a", Module: "module", Arch: "i686"},
		},
		CPEs: []string{"cpe-a", "cpe2-a"},
	}

	layer1b := &database.RHELv2Layer{
		Hash:          "sha256:layer1-b",
		Lineage:       "lineage",
		ParentHash:    "sha256:base",
		ParentLineage: "",
		Dist:          "rhel:8",
		Pkgs: []*database.RHELv2Package{
			{Name: "pkg", Version: "v1-b", Arch: "x86_64"},
			{Name: "pkg2", Version: "v2-b", Module: "module", Arch: "i686"},
		},
		CPEs: []string{"cpe-b", "cpe2-b"},
	}

	err = datastore.InsertRHELv2Layer(layer1a)
	require.NoError(t, err)
	err = datastore.InsertRHELv2Layer(layer1b)
	require.NoError(t, err)

	leafa := &database.RHELv2Layer{
		Hash:          "sha256:leaf", // for this test all leafs should have same digest
		Lineage:       "lineage-a",   // lineage is specific to layer A
		ParentHash:    "sha256:layer1-a",
		ParentLineage: "lineage",
		Dist:          "rhel:8",
	}

	var leafb = new(database.RHELv2Layer)
	*leafb = *leafa
	leafb.Lineage = "lineage-b"
	leafb.ParentHash = "sha256:layer1-b"

	err = datastore.InsertRHELv2Layer(leafa)
	require.NoError(t, err)
	err = datastore.InsertRHELv2Layer(leafb)
	require.NoError(t, err)

	assertLayersEqual := func(t *testing.T, expected, actual *database.RHELv2Layer) {
		resetPackageIDs(actual)
		assert.Equal(t, expected.Hash, actual.Hash, "Hash mismatch")
		assert.Equal(t, expected.Lineage, actual.Lineage, "Lineage mismatch")
		assert.Equal(t, expected.CPEs, actual.CPEs, "CPEs mistmatch")
		assert.Equal(t, expected.Pkgs, actual.Pkgs, "Pkgs mismatch")
	}

	layers, err := datastore.GetRHELv2Layers("sha256:leaf", "lineage-a")
	require.NoError(t, err)
	require.Len(t, layers, 3)

	assertLayersEqual(t, base, layers[0])
	assertLayersEqual(t, layer1a, layers[1])
	assertLayersEqual(t, leafa, layers[2])

	layers, err = datastore.GetRHELv2Layers("sha256:leaf", "lineage-b")
	require.NoError(t, err)
	require.Len(t, layers, 3)

	assertLayersEqual(t, base, layers[0])
	assertLayersEqual(t, layer1b, layers[1])
	assertLayersEqual(t, leafb, layers[2])
}

// resetPackageIDs sets all package IDs to 0. Package IDs are DB sequence numbers
// that will not be deterministic (depending on how tests are written), therefore
// set the IDs to 0 to allow tests pass.
func resetPackageIDs(layer *database.RHELv2Layer) {
	for _, pkg := range layer.Pkgs {
		pkg.ID = 0
	}
}
