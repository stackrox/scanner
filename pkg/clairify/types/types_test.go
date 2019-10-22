package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateImageFromString(t *testing.T) {
	expectedImage := &Image{
		Registry: "docker.io",
		Remote:   "library/nginx",
		Tag:      "1.10",
	}

	i, err := GenerateImageFromString("nginx:1.10")
	assert.NoError(t, err)
	assert.Equal(t, expectedImage, i)

	i, err = GenerateImageFromString("library/nginx:1.10")
	assert.NoError(t, err)
	assert.Equal(t, expectedImage, i)

	i, err = GenerateImageFromString("docker.io/library/nginx:1.10")
	assert.NoError(t, err)
	assert.Equal(t, expectedImage, i)
}
