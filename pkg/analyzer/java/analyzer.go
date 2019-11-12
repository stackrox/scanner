package java

import (
	"os"

	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) bool {
	return match(fullPath)
}

func match(fullPath string) bool {
	return javaRegexp.MatchString(fullPath)
}

func addVersion(c *component.Component) {
	if c.JavaPkgMetadata == nil {
		return
	}
	c.Version = stringutils.FirstNonEmpty(c.JavaPkgMetadata.MavenVersion, c.JavaPkgMetadata.ImplementationVersion, c.JavaPkgMetadata.SpecificationVersion)
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var allComponents []*component.Component
	for filePath, contents := range fileMap {
		if !match(filePath) || len(contents) == 0 {
			continue
		}
		components, err := parseContents(filePath, contents)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}
	for _, c := range allComponents {
		addVersion(c)
	}
	return component.FilterToOnlyValid(allComponents), nil
}

func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
