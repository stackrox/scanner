package common

import (
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// ExtractComponents is a utility function that extracts out the logic common to most analyzers.
func ExtractComponents(fileMap tarutil.FilesMap, matchFunc func(filePath string) bool, extractFunc func(filePath string, contents []byte) *component.Component) []*component.Component {
	var allComponents []*component.Component
	for filePath, contents := range fileMap {
		if !matchFunc(filePath) {
			continue
		}
		if c := extractFunc(filePath, contents.GetContents()); c != nil {
			allComponents = append(allComponents, c)
		}
	}
	return component.FilterToOnlyValid(allComponents)
}
