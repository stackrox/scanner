// +build integration

package psql

import (
	"testing"

	"github.com/stackrox/scanner/pkg/clairify/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPSQL(t *testing.T) {
	p, err := New("localhost", "postgres", "", "disable")
	if err != nil {
		require.NoError(t, err)
	}

	i := types.Image{
		SHA:       "sha1",
		Registry:  "registry1",
		Namespace: "namespace1",
		Repo:      "repo1",
		Tag:       "tag1",
	}

	layerName := "layer1"
	assert.NoError(t, p.AddImage(layerName, i))
	// Check that adding duplicate times does not result in an error
	assert.NoError(t, p.AddImage(layerName, i))

	// Check layer by Name exists
	layer, exists, err := p.GetLayerByName(i.String())
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, layerName, layer)

	// Check layer by SHA exists
	layer, exists, err = p.GetLayerBySHA(i.SHA)
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, layerName, layer)

	// Check not exists
	layer, exists, err = p.GetLayerByName("blah")
	assert.NoError(t, err)
	assert.False(t, exists)

	layer, exists, err = p.GetLayerBySHA("blah")
	assert.NoError(t, err)
	assert.False(t, exists)
}
