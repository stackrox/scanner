package golang

import (
	"io"
	"os"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct {
	components []*component.Component
}

func (a *analyzerImpl) Match(fullPath string, fileInfo os.FileInfo, contents io.ReaderAt) (matches bool, extract bool) {
	if fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0111 == 0 {
		return false, false
	}

	a.components = append(a.components, analyzeGoBinary(fullPath, contents)...)
	return false, false
}

func (a *analyzerImpl) Analyze(_ tarutil.FilesMap) ([]*component.Component, error) {
	ret := a.components
	a.components = nil
	return component.FilterToOnlyValid(ret), nil
}

// Analyzer returns the Golang analyzer.
func Analyzer() analyzer.Analyzer {
	return &analyzerImpl{}
}
