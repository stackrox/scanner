package analyzer

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// An Analyzer analyzes images and extracts the components present in them.
type Analyzer interface {
	Analyze(*database.Namespace, tarutil.FilesMap) ([]*component.Component, error)
	matcher.Matcher
}

func Analyze(namespace *database.Namespace, filesMap tarutil.FilesMap, analyzers []Analyzer) ([]*component.Component, error) {
	var allComponents []*component.Component
	for _, a := range analyzers {
		components, err := a.Analyze(namespace, filesMap)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, components...)
	}

	return allComponents, nil
}
