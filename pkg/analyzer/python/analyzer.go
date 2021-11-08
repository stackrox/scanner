package python

import (
	"io"
	"os"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	// We support Python files in wheel and egg distributions.
	allowedSuffixes = []string{
		// The following are the file paths for egg distributions.
		// See https://setuptools.readthedocs.io/en/latest/formats.html#project-metadata for details.
		".egg/EGG-INFO/PKG-INFO",
		".egg-info/PKG-INFO",
		// It is legal for the .egg-info directory to, well, be a file and not the directory
		// and directly contain the PKG-INFO data. This handles that case.
		".egg-info",

		// This is the file path for wheel distributions.
		// See https://www.python.org/dev/peps/pep-0427/#the-dist-info-directory
		".dist-info/METADATA",
	}
)

type analyzerImpl struct{}

func (analyzerImpl) ProcessFile(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) []*component.Component {
	if fileInfo.IsDir() || !matchSuffix(fullPath) {
		return nil
	}

	if c := parseMetadataFile(fullPath, io.NewSectionReader(contents, 0, fileInfo.Size())); c != nil {
		return []*component.Component{c}
	}
	return nil
}

func matchSuffix(fullPath string) bool {
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(fullPath, suffix) {
			return true
		}
	}
	return false
}

// Analyzer returns the Python analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
