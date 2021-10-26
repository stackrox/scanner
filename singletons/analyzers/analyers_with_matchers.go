package analyzers

import (
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/dotnetcoreruntime"
	"github.com/stackrox/scanner/pkg/analyzer/gem"
	"github.com/stackrox/scanner/pkg/analyzer/golang"
	"github.com/stackrox/scanner/pkg/analyzer/java"
	"github.com/stackrox/scanner/pkg/analyzer/npm"
	"github.com/stackrox/scanner/pkg/analyzer/python"
)

var (
	analyzerFactories = []analyzer.Factory{
		dotnetcoreruntime.Analyzer,
		gem.Analyzer,
		java.Analyzer,
		npm.Analyzer,
		python.Analyzer,
		golang.Analyzer,
	}
)

// AnalyzerFactories returns all the application-level analyzerFactories.
func AnalyzerFactories() []analyzer.Factory {
	return analyzerFactories
}
