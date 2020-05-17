package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAuth(t *testing.T) {
	expectedUsername := "username"
	expectedPassword := "password"
	base64Header := "Basic dXNlcm5hbWU6cGFzc3dvcmQK"

	// validate base64
	user, pass, err := getAuth(base64Header)
	assert.NoError(t, err)
	assert.Equal(t, expectedUsername, user)
	assert.Equal(t, expectedPassword, pass)

	_, _, err = getAuth("")
	assert.NoError(t, err)

	_, _, err = getAuth("Bearer dXNlcm5hbWU6cGFzc3dvcmQK")
	assert.Error(t, err)

	// Base64 encoded improperly via  echo "username" | base64
	base64Header = "Basic dXNlcm5hbWUK"
	_, _, err = getAuth(base64Header)
	assert.Error(t, err)

	// Too many ":"s via echo "username:password:token" | base64
	// Passwords can contain : so there should not be an error
	base64Header = "Basic dXNlcm5hbWU6cGFzc3dvcmQ6dG9rZW4K"
	_, _, err = getAuth(base64Header)
	assert.NoError(t, err)
}

func TestParseImagePath(t *testing.T) {
	cases := []struct {
		path, image string
		expectError bool
	}{
		{
			path:        "/scanner/image/docker.io/library/nginx/latest",
			image:       "docker.io/library/nginx:latest",
			expectError: false,
		},
		{
			path:        "/scanner/image/stackrox.io/main/3.0.42.0",
			image:       "stackrox.io/main:3.0.42.0",
			expectError: false,
		},
		{
			path:        "/scanner/image/docker.pkg.github.com/stackrox/rox/ubuntu/14.04",
			image:       "docker.pkg.github.com/stackrox/rox/ubuntu:14.04",
			expectError: false,
		},
		{
			path:        "/scanner/image/",
			image:       "",
			expectError: true,
		},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			image, err := parseImagePath(c.path)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.image, image)
		})
	}
}
