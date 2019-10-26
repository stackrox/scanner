package java

import (
	"path/filepath"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(filePath string) bool {
	return javaRegexp.MatchString(filepath.Base(filePath))
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var allComponents []*component.Component
	for filePath, contents := range fileMap {
		if !a.Match(filePath) {
			continue
		}
		packages, err := parseContents(filePath, contents)
		if err != nil {
			return nil, err
		}
		for _, p := range packages {
			allComponents = append(allComponents, &component.Component{
				JavaPkgMetadata: p,
			})
		}
	}
	return allComponents, nil
}

func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
