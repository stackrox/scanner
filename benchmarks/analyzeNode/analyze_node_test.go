package detectconent

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"

	node "github.com/stackrox/scanner/pkg/analyzer/nodes"
	// Register the Docker image extractor
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
)

func BenchmarkAnalyzeNode(b *testing.B) {
	var path = os.Getenv("RHCOS_TEST_PATH")
	if len(path) < 1 {
		b.Fatal("Invalid file path")
	}
	fmt.Printf("Current path to file system is: %s", path)
	fmt.Println()
	runBenchmarkAnalyzeNode(b, path)
}

func runBenchmarkAnalyzeNode(b *testing.B, pathName string) {
	runtime.GC()

	for i := 0; i < b.N; i++ {
		node.Analyze(context.Background(), "testNode", pathName, node.AnalyzeOpts{UncertifiedRHEL: false, IsRHCOSRequired: false})
	}
	// Memory measuring command: go test -bench=foo -benchmem

}
