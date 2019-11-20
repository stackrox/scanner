package python

import (
	"bufio"
	"bytes"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
)

// Package managers find these libraries and are a more complete source of vulnerabilities
// as opposed to CPEs
var disallowedPkgs = set.NewFrozenStringSet("python")

// The metadata file format is specified at https://packaging.python.org/specifications/core-metadata/.
// Note that it's possible that the file is not a Python manifest but some other totally random file that
// happens to have a matching name.
// In this case, this function will gracefully return `nil`.
func parseMetadataFile(filePath string, contents []byte) *component.Component {
	var c *component.Component

	ensureCInitialized := func() {
		if c == nil {
			c = &component.Component{
				Location:   filePath,
				SourceType: component.PythonSourceType,
			}
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		currentLine := scanner.Text()
		key, value := stringutils.Split2(currentLine, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" || key == "" {
			continue
		}
		switch key {
		case "Name":
			ensureCInitialized()
			c.Name = value
		case "Version":
			ensureCInitialized()
			c.Version = value
		}

		// If we have got all the information we want, no point in scanning the rest of the file.
		if common.HasNameAndVersion(c) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error scanning file %q: %v", filePath, err)
		return nil
	}

	if c == nil {
		return nil
	}
	if disallowedPkgs.Contains(strings.ToLower(c.Name)) {
		return nil
	}

	return c
}
