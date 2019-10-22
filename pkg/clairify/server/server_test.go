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
	assert.Error(t, err)

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
