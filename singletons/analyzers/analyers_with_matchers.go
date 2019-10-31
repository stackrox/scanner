package analyzers

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/java"
	"github.com/stackrox/scanner/pkg/analyzer/python"
)

var (
	analyzers = []analyzer.Analyzer{
		java.Analyzer(),
		python.Analyzer(),
	}
)

func Analyzers() []analyzer.Analyzer {
	return analyzers
}
