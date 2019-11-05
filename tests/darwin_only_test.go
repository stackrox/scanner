//+build darwin

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	dockerCredentialHelpers "github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/osxkeychain"
)

func maybeGetFromKeyChain() (string, string) {
	var buffer bytes.Buffer
	err := dockerCredentialHelpers.Get(osxkeychain.Osxkeychain{}, strings.NewReader("docker.io"), &buffer)
	if err != nil {
		fmt.Printf("Error getting credentials: %v\n", err)
		return "", ""
	}
	var creds dockerCredentialHelpers.Credentials
	err = json.Unmarshal(buffer.Bytes(), &creds)
	if err != nil {
		fmt.Printf("Error unmarshaling docker credentials JSON: %v\n", err)
		return "", ""
	}
	return creds.Username, creds.Secret
}
