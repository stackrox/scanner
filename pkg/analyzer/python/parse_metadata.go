package python

import (
	"bufio"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/component"
)

// Package managers find these libraries and are a more complete source of vulnerabilities
// as opposed to CPE
var disallowedPkgs = set.NewFrozenStringSet("python")

// The metadata file format is specified at https://packaging.python.org/specifications/core-metadata/.
// Note that it's possible that the file is not a Python manifest but some other totally random file that
// happens to have a matching name.
// In this case, this function will gracefully return `nil`.
func parseMetadataFile(filePath string, fi os.FileInfo, contents io.ReaderAt) *component.Component {
	c := &component.Component{
		Location:          filePath,
		SourceType:        component.PythonSourceType,
		PythonPkgMetadata: &component.PythonPkgMetadata{},
	}

	scanner := bufio.NewScanner(io.NewSectionReader(contents, 0, fi.Size()))
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
			c.Name = value
		case "Version":
			c.Version = value
		case "Home-page":
			c.PythonPkgMetadata.Homepage = value
		case "Author-email":
			c.PythonPkgMetadata.AuthorEmail = value
		case "Summary":
			c.PythonPkgMetadata.Summary = value
		case "Description":
			c.PythonPkgMetadata.Description = value
		case "Download-URL":
			c.PythonPkgMetadata.DownloadURL = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error scanning file %q: %v", filePath, err)
		return nil
	}

	if !stringutils.AllNotEmpty(c.Name, c.Version) {
		return nil
	}

	if disallowedPkgs.Contains(strings.ToLower(c.Name)) {
		return nil
	}

	return c
}
