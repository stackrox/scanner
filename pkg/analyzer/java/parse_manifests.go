package java

import (
	"archive/zip"
	"bufio"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/stackrox/rox/pkg/stringutils"
)

const (
	manifestFileName = `META-INF/MANIFEST.MF`
)

var (
	semverRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)
)

type parsedManifestMF struct {
	specificationVersion string
	specificationVendor  string

	implementationVersion  string
	implementationVendor   string
	implementationVendorID string
	bundleName             string
	bundleSymbolicName     string
}

func parseVersionOutOfName(jar string) string {
	jarBase := filepath.Base(jar)
	jarBase = strings.TrimSuffix(jarBase, ".jar")
	jarBase = strings.TrimSuffix(jarBase, "-fatjar")

	if idx := strings.LastIndex(jarBase, "-"); idx != -1 && idx != len(jarBase)-1 {
		version := jarBase[idx+1:]
		if semverRegex.MatchString(version) {
			return version
		}
	}
	return ""
}

func parseManifestMFFromReader(locationSoFar string, reader io.Reader) (parsedManifestMF, error) {
	var currentValueToSet *string
	var currentValue string
	var manifest parsedManifestMF
	var isTemplatedManifestFile bool

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		currentLine := scanner.Text()
		// This means that the valueFromLine is a continuation of the valueFromLine for the previous keyFromLine.
		if strings.HasPrefix(currentLine, " ") {
			if currentValueToSet != nil {
				currentValue += currentLine[1:]
			}
			continue
		}

		// Whatever the previous valueFromLine was, we've seen it in full at this point.
		if currentValueToSet != nil {
			*currentValueToSet = strings.TrimSpace(currentValue)
			currentValueToSet = nil
		}
		keyFromLine, valueFromLine := stringutils.Split2(currentLine, ":")
		// Should never happen, probably a malformed JAR file?
		// Sometimes the Manifests are templated with ${revision} or ${version}
		if valueFromLine == "" {
			continue
		}
		if strings.Contains(valueFromLine, "$") {
			isTemplatedManifestFile = true
			continue
		}
		valueFromLine = strings.TrimSpace(valueFromLine)
		keyFromLine = strings.TrimSpace(strings.TrimSpace(keyFromLine))
		switch keyFromLine {
		case "Specification-Version":
			currentValueToSet = &manifest.specificationVersion
		case "Specification-Vendor":
			currentValueToSet = &manifest.specificationVendor
		case "Implementation-Version":
			currentValueToSet = &manifest.implementationVersion
		case "Implementation-Vendor":
			currentValueToSet = &manifest.implementationVendor
		case "Implementation-Vendor-Id":
			currentValueToSet = &manifest.implementationVendorID
		case "Bundle-Name":
			currentValueToSet = &manifest.bundleName
		case "Bundle-SymbolicName":
			currentValueToSet = &manifest.bundleSymbolicName
		}
		if currentValueToSet != nil && *currentValueToSet == "" {
			currentValue = valueFromLine
		} else {
			currentValueToSet = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return parsedManifestMF{}, err
	}
	if currentValueToSet != nil {
		*currentValueToSet = strings.TrimSpace(currentValue)
		// Ignore linting for potential future-proofing purposes.
		currentValueToSet = nil //nolint:ineffassign
	}

	// Try to take the version from the jar name
	if manifest.implementationVersion == "" && isTemplatedManifestFile {
		manifest.implementationVersion = parseVersionOutOfName(locationSoFar)
	}

	return manifest, nil
}

func parseManifestMF(locationSoFar string, f *zip.File) (parsedManifestMF, error) {
	reader, err := f.Open()
	if err != nil {
		return parsedManifestMF{}, err
	}
	defer func() {
		_ = reader.Close()
	}()

	return parseManifestMFFromReader(locationSoFar, reader)
}

type parsedPomProps struct {
	version    string
	groupID    string
	artifactID string
}

func parseMavenPomProperties(f *zip.File) (parsedPomProps, error) {
	reader, err := f.Open()
	if err != nil {
		return parsedPomProps{}, err
	}
	defer func() {
		_ = reader.Close()
	}()

	var props parsedPomProps

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		currentLine := scanner.Text()
		if strings.HasPrefix(currentLine, "#") {
			continue
		}
		key, value := stringutils.Split2(currentLine, "=")
		// TODO(viswa): Maybe better logging. This should never happen.
		if value == "" {
			continue
		}
		switch key {
		case "version":
			props.version = value
		case "groupId":
			props.groupID = value
		case "artifactId":
			props.artifactID = value
		}
	}
	if err := scanner.Err(); err != nil {
		return parsedPomProps{}, err
	}
	return props, nil
}
