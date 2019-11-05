// +build !darwin

package tests

// The keychain stuff doesn't work on Linux.
func maybeGetFromKeyChain() (string, string) {
	return "", ""
}
