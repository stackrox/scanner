package golang

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) (matches bool, extract bool) {
	log.Infof("Evaluating path %s", fullPath)
	if fileInfo.IsDir() {
		log.Info("Discarding - is directory")
		return false, false
	}
	if fileInfo.Mode().Perm()&0111 == 0 {
		log.Info("Discarding - is not executable")
	}
	log.Info("%s matches!", fullPath)
	return true, true
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var components []*component.Component
	for filePath, fileData := range fileMap {
		if !fileData.Executable {
			log.Infof("Skipping file %s as it is not executable", filePath)
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
