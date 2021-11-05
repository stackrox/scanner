package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUUID(t *testing.T) {
	uuid, err := getUUID("gs://definitions.stackrox.io/5ca69bf7-08ab-4f17-9e4f-e342a020d977/diff.zip")
	assert.NoError(t, err)
	assert.Equal(t, "5ca69bf7-08ab-4f17-9e4f-e342a020d977", uuid)

	uuid, err = getUUID("5ca69bf7-08ab-4f17-9e4f-e342a020d977")
	assert.NoError(t, err)
	assert.Equal(t, "5ca69bf7-08ab-4f17-9e4f-e342a020d977", uuid)

	_, err = getUUID("not a uuid")
	assert.Error(t, err)
}
