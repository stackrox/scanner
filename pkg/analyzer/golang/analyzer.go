package golang

import (
	"os"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) (matches bool, extract bool) {
	if fileInfo.IsDir() {
		return false, false
	}
	return fileInfo.Mode().Perm()&0111 != 0, false
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var components []*component.Component
	for filePath, fileData := range fileMap {
		if !fileData.Executable {
			continue
		}
		components = append(components, analyzeGoBinary(filePath, fileData.Contents)...)
	}

	return component.FilterToOnlyValid(components), nil
}

// Analyzer returns the Golang analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
