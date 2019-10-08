package analyzers

import (
	"github.com/stackrox/scanner/pkg/filemap"
	"github.com/stackrox/scanner/pkg/types"
)

var (
	analyzers = make(map[string]Analyzer)
)

type Analyzer interface {
	Match(filePath string) bool
	Extract(fileMap filemap.FileMap) ([]types.Component, error)
}

func Register(name string, a Analyzer) {
	analyzers[name] = a
}

func List() []Analyzer {
	l := make([]Analyzer, 0, len(analyzers))
	for _, a := range analyzers {
		l = append(l, a)
	}
	return l
}
