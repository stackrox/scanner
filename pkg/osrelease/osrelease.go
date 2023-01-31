package osrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/ext/featurens/util"
)

var (
	osPattern      = regexp.MustCompile(`^ID=(.*)`)
	versionPattern = regexp.MustCompile(`^VERSION_ID=(.*)`)
)

// GetOSAndVersionFromOSRelease returns the value of ID= and VERSION_ID= from /etc/os-release formatted data
func GetOSAndVersionFromOSRelease(data []byte) (os, version string) {
	m := GetOSReleaseMap(data, "ID", "VERSION_ID")
	return util.NormalizeOSName(m["ID"]), m["VERSION_ID"]
}

// GetOSReleaseMap returns a map where keys and value are extracted from the
// given os-release data. If `fields` is specified, only those fields are
// returned. If None found empty map is returned.
func GetOSReleaseMap(data []byte, fields ...string) map[string]string {
	fieldsSet := set.NewStringSet(fields...)
	osReleaseMap := make(map[string]string)
	// The format of os-release is a newline-separated list of
	// environment-like shell-compatible variable assignments.
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			// Ignore malformed or empty lines.
			continue
		}
		key := parts[0]
		if len(fields) == 0 || fieldsSet.Contains(key) {
			osReleaseMap[key] = strings.Replace(strings.ToLower(strings.TrimSpace(parts[1])), `"`, "", -1)
		}
	}
	return osReleaseMap
}
