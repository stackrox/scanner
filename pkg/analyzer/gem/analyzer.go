package gem

import (
	"os"
	"regexp"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

var (
	gemSpecRegexp = regexp.MustCompile(`.*specifications/.*\.gemspec`)
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, _ os.FileInfo) (matches bool, extract bool) {
	return match(fullPath), true
}

func match(fullPath string) bool {
	return gemSpecRegexp.MatchString(fullPath)
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	return common.ExtractComponents(fileMap, match, parseGemSpec), nil
}

// Analyzer returns a Ruby Gem analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
