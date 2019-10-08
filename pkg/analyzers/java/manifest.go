package java

import (
	"archive/zip"
	"bufio"
	"log"
	"strings"
)

const (
	manifestFileName = `META-INF/MANIFEST.MF`
)

type parsedManifest struct {
	specificationVersion string
	specificationVendor  string

	implementationVersion string
	implementationVendor  string
}

func maybeParseManifest(f *zip.File) (*parsedManifest, error) {
	if f.Name != manifestFileName {
		return nil, nil
	}
	reader, err := f.Open()
	if err != nil {
		return nil, err
	}

	var currentValueToSet *string
	var currentValue string
	scanner := bufio.NewScanner(reader)
	manifest := new(parsedManifest)
	for scanner.Scan() {
		currentLine := scanner.Text()
		// This means that the value is a continuation of the value for the previous key.
		if strings.HasPrefix(currentLine, " ") {
			if currentValueToSet != nil {
				currentValue += currentLine[1:]
			}
			continue
		}

		// Whatever the previous value was, we've seen it in full at this point.
		if currentValueToSet != nil {
			*currentValueToSet = currentValue
			currentValueToSet = nil
		}
		splitString := strings.SplitN(currentLine, ":", 2)
		// Should never happen, probably a malformed JAR file?
		if len(splitString) < 2 {
			continue
		}

		key := strings.TrimSpace(splitString[0])
		switch key {
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
			currentValue = splitString[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// TODO(viswa): Improve logging.
	if currentValueToSet == nil {
		log.Print("ERROR: CurrentValueToSet was not nil")
	}
	return manifest, nil
}
