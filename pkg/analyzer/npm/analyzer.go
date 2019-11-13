package npm

import (
	"os"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) bool {
	return match(fullPath)
}

func match(fullPath string) bool {
	// Check for node modules to ensure it is actually a NodeJS module
	return strings.Contains(fullPath, "node_modules") && strings.HasSuffix(fullPath, "/package.json")
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	return common.ExtractComponents(fileMap, match, parsePackageJSON), nil
}

func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
