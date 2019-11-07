package analyzers

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/gem"
	"github.com/stackrox/scanner/pkg/analyzer/java"
	"github.com/stackrox/scanner/pkg/analyzer/npm"
	"github.com/stackrox/scanner/pkg/analyzer/python"
)

var (
	analyzers = []analyzer.Analyzer{
		gem.Analyzer(),
		java.Analyzer(),
		npm.Analyzer(),
		python.Analyzer(),
	}
)

func Analyzers() []analyzer.Analyzer {
	return analyzers
}
