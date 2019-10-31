package java

import (
	"archive/zip"
	"bufio"
	"strings"

	"github.com/stackrox/rox/pkg/stringutils"
)

const (
	manifestFileName = `META-INF/MANIFEST.MF`
)

type parsedManifestMF struct {
	specificationVersion string
	specificationVendor  string

	implementationVersion string
	implementationVendor  string
}

func parseManifestMF(f *zip.File) (parsedManifestMF, error) {
	reader, err := f.Open()
	if err != nil {
		return parsedManifestMF{}, err
	}
	defer func() {
		_ = reader.Close()
	}()

	var currentValueToSet *string
	var currentValue string
	var manifest parsedManifestMF

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
		if valueFromLine == "" {
			continue
		}

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
		}
		if currentValueToSet != nil {
			currentValue = valueFromLine
		}
	}

	if err := scanner.Err(); err != nil {
		return parsedManifestMF{}, err
	}
	if currentValueToSet != nil {
		*currentValueToSet = strings.TrimSpace(currentValue)
		currentValueToSet = nil
	}
	return manifest, nil
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
