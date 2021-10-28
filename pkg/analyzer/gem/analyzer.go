package gem

import (
	"io"
	"os"
	"regexp"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	gemSpecRegexp = regexp.MustCompile(`.*specifications/.*\.gemspec`)
)

type analyzerImpl struct{}

func (analyzerImpl) ProcessFile(fullPath string, fi os.FileInfo, contents io.ReaderAt) []*component.Component {
	if !match(fullPath) {
		return nil
	}
	if c := parseGemSpec(fullPath, fi, contents); c != nil {
		return []*component.Component{c}
	}
	return nil
}

func match(fullPath string) bool {
	return gemSpecRegexp.MatchString(fullPath)
}

// Analyzer returns a Ruby Gem analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
