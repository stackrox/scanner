package analyzers

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/java"
)

var (
	analyzers = []analyzer.Analyzer{
		java.Analyzer(),
	}
)

func Analyzers() []analyzer.Analyzer {
	return analyzers
}
