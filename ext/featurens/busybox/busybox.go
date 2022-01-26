// Package busybox implements a featurens.Detector for container images
// layers based on busybox[1].
//
// [1]: https://www.busybox.net/FAQ.html
//
// The detector assumes a Busybox image has the following attributes:
//
// 1. Does not contain any freedesktop standard release file (os-release, lsb-release).
//
// 2. `/bin/sh` and `/bin/busybox` are hard-links. In the image tarball their content is
//    stored in `/bin/[`.
//
// 3. The busybox binary contains a version string on the form "BusyBox vX.Y.Z"
//
package busybox

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type detector struct{}

var (
	busyboxVersionMatcher = regexp.MustCompile(`BusyBox v(\d)+\.(\d)+\.(\d)+`)
	blockedFiles          = []string{
		"etc/os-release",
		"etc/lsb-release",
		"usr/lib/os-release",
		"usr/lib/lsb-release",
	}
)

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

func (detector) Detect(files tarutil.LayerFiles, options *featurens.DetectorOptions) *database.Namespace {
	for _, filePath := range blockedFiles {
		if _, hasFile := files.Get(filePath); hasFile {
			return nil
		}
	}

	busyboxData, ok := files.Get("bin/busybox")
	if !ok {
		return nil
	}
	shData, ok := files.Get("bin/sh")
	if !ok {
		return nil
	}

	// We assume ``/bin/sh`` hard links to busybox, to guard against the odds of an
	// image shipping different coreutils being classified as busybox.
	if !bytes.Equal(busyboxData.Contents, shData.Contents) {
		return nil
	}

	// Validate busybox binary and extract version.
	var version = parseBusyBoxVersion(busyboxData.Contents)
	if version == "" {
		return nil
	}

	return &database.Namespace{
		Name:          "busybox" + ":" + version,
		VersionFormat: language.ParserName,
	}
}

func (detector) RequiredFilenames() []string {
	// FIXME Currently we cannot extract contents of hard links unless we explicitly
	//       whitelist its target; In tar that's a previously archived file, which
	//       we observed to be ``/bin/[``.
	return []string{"bin/sh", "bin/busybox"}
}
