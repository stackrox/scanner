package python

import (
	"bufio"
	"bytes"
	"log"
	"strings"

	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/component"
)

// The metadata file format is specified at https://packaging.python.org/specifications/core-metadata/.
// Note that it's possible that the file is not a Python manifest but some other totally random file that
// happens to have a matching name.
// In this case, this function will simply return `nil`.
func parseMetadataFile(filePath string, contents []byte) *component.Component {
	var c *component.Component

	ensureCNotNil := func() {
		if c == nil {
			c = &component.Component{}
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
			ensureCNotNil()
			c.Name = value
		case "Version":
			ensureCNotNil()
			c.Version = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning file %q: %v", filePath, err)
		return nil
	}

	if c == nil {
		return nil
	}
	c.Location = filePath
	return c
}
