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
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	for i := 0; i < b.N; i++ {
		node.Analyze("testNode", pathName, node.AnalyzeOpts{UncertifiedRHEL: false, IsRHCOSRequired: true})
	}
	runtime.ReadMemStats(&m2)
	// Memory measuring command: go test -bench=foo -benchmem

}
