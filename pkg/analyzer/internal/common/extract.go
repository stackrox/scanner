package common

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

type matchFn func(path string) bool
type extractFn func(path string, contents []byte) *component.Component

// ExtractComponents is a utility function that extracts out the logic common to most analyzers.
func ExtractComponents(fileMap tarutil.FilesMap, matchFunc matchFn, extractFunc extractFn, opts analyzer.AnalyzeOptions) []*component.Component {
	var allComponents []*component.Component
	for filePath, contents := range fileMap {
		if !matchFunc(filePath) {
			continue
		}
		if !opts.FilterFn(filePath) {
			continue
		}
		if c := extractFunc(filePath, contents); c != nil {
			allComponents = append(allComponents, c)
		}
	}
	return component.FilterToOnlyValid(allComponents)
}
