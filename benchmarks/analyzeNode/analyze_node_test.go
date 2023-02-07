package detectconent

import (
	"runtime"
	"testing"

	node "github.com/stackrox/scanner/pkg/analyzer/nodes"
	// Register the Docker image extractor
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
)

func BenchmarkAnalyzeNode(b *testing.B) {
	runBenchmarkAnalyzeNode(b, "/local/path/to/file/system")
}

func runBenchmarkAnalyzeNode(b *testing.B, pathName string) {
	runtime.GC()

	for i := 0; i < b.N; i++ {
		node.Analyze("testNode", pathName, node.AnalyzeOpts{UncertifiedRHEL: false, IsRHCOSRequired: false})
	}
	// Memory measuring command: go test -bench=foo -benchmem

}
