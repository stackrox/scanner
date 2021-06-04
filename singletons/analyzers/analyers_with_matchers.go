package analyzers

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/dotnetcoreruntime"
	"github.com/stackrox/scanner/pkg/analyzer/gem"
	"github.com/stackrox/scanner/pkg/analyzer/java"
	"github.com/stackrox/scanner/pkg/analyzer/npm"
	"github.com/stackrox/scanner/pkg/analyzer/python"
)

var (
	analyzers = []analyzer.Analyzer{
		dotnetcoreruntime.Analyzer(),
		gem.Analyzer(),
		java.Analyzer(),
		npm.Analyzer(),
		python.Analyzer(),
	}
)

// Analyzers returns all the application-level analyzers.
func Analyzers() []analyzer.Analyzer {
	return analyzers
}
