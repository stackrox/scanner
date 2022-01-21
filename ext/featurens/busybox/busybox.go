// Package busybox implements a featurens.Detector for container images
// layers based on busybox[1].
//
// [1]: https://www.busybox.net/FAQ.html
//
// The detector assumes a Busybox image has the following attributes:
//
// 1. Does not contain any freedesktop standard release file (os-release, lsb-release).
//
// 2. `/bin/sh` and `/bin/busybox` are hard-links to `/bin/[`, the actual regular file
//    shipping Busybox, as observed in the container image.
//
package busybox

import (
	"regexp"
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type detector struct{}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d.]+`)

func init() {
	featurens.RegisterDetector("busybox", &detector{})
}

func parseBusyBoxVersion(contents []byte) string {
	matches := busyboxVersionMatcher.FindAllString(string(contents), -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")
		return version
	}
	return ""
}

func (detector) Detect(filesMap tarutil.FilesMap, options *featurens.DetectorOptions) *database.Namespace {
	var blockedFiles = []string{
		"etc/os-release",
		"etc/lsb-release",
		"usr/lib/os-release",
		"usr/lib/lsb-release",
	}
	for _, filePath := range blockedFiles {
		if _, hasFile := filesMap[filePath]; hasFile {
			return nil
		}
	}

	// Check the actual busybox path, notice `bin/busybox` itself might be a link
	// to another file, and that's OK.

	var busyboxPath = "bin/busybox"
	if filesMap[busyboxPath].LinkName != "" {
		actualPath := filesMap[busyboxPath].LinkName
		if _, ok := filesMap[actualPath]; !ok {
			return nil
		}
		busyboxPath = actualPath
	}

	// We assume /bin/sh should link to busybox, to guard against the odds of an
	// image shipping different coreutils being classified as busybox.
	if filesMap["bin/sh"].LinkName != busyboxPath {
		return nil
	}

	// Get busybox version, if not found we report unknown, but assume busybox.
	var version = parseBusyBoxVersion(filesMap[busyboxPath].Contents)
	if version == "" {
		version = "unknown"
	}

	return &database.Namespace{
		Name:          "busybox" + ":v" + version,
		VersionFormat: language.ParserName,
	}
}

func (detector) RequiredFilenames() []string {
	return []string{"bin/sh", "bin/[", "bin/busybox"}
}
