package osrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/ext/featurens/util"
)

var (
	osReleaseOSRegexp      = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp = regexp.MustCompile(`^VERSION_ID=(.*)`)
)

// GetIDFromOSRelease returns the value of ID= from /etc/os-release formatted data
func GetIDFromOSRelease(data []byte) (os, version string) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		r := osReleaseOSRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			os = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
		}

		r = osReleaseVersionRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
		}
	}
	return util.NormalizeOSName(os), version
}
