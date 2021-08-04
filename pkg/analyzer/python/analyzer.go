package python

import (
	"os"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
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

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) (match bool, extract bool) {
	if fileInfo.IsDir() {
		return false, false
	}

	return matchSuffix(fullPath), true
}

func matchSuffix(fullPath string) bool {
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(fullPath, suffix) {
			return true
		}
	}
	return false
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	return common.ExtractComponents(fileMap, matchSuffix, parseMetadataFile), nil
}

// Analyzer returns the Python analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
