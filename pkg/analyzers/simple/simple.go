package simple

import (
	"github.com/stackrox/scanner/pkg/analyzers"
	"github.com/stackrox/scanner/pkg/filemap"
	"github.com/stackrox/scanner/pkg/types"
)

type Analyzer struct {
}

func (Analyzer) Match(filePath string) bool {
	return filePath == "bin/cat"
}

func (Analyzer) Extract(fileMap filemap.FileMap) ([]types.Component, error) {
	if _, ok := fileMap["bin/cat"]; ok {
		return []types.Component{
			{Name: "CAT", Version: "1.0"},
		}, nil
	}
	return nil, nil
}

func init() {
	analyzers.Register("Simple", Analyzer{})
}
