package npm

import (
	"io"
	"os"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
)

type analysisImpl struct{}

func (analysisImpl) ProcessFile(fullPath string, fi os.FileInfo, contents io.ReaderAt) []*component.Component {
	if !match(fullPath) {
		return nil
	}
	if c := parsePackageJSON(fullPath, fi, contents); c != nil {
		return []*component.Component{c}
	}
	return nil
}

func match(fullPath string) bool {
	// Check for node modules to ensure it is actually a NodeJS module
	return (strings.Contains(fullPath, "node_modules") || strings.Contains(fullPath, "nodejs")) && strings.HasSuffix(fullPath, "/package.json")
}

// Analyzer returns the NPM analyzer.
func Analyzer() analyzer.Analyzer {
	return analysisImpl{}
}
