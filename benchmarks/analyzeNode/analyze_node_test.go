package detectconent

import (
	"fmt"
	"runtime"
	"testing"

	node "github.com/stackrox/scanner/pkg/analyzer/nodes"
	"github.com/stretchr/testify/require"

	// Register the Docker image extractor
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
)

func BenchmarkAnalyzeNode(b *testing.B) {
	runBenchmarkAnalyzeNode(b, "fake path")
}

func runBenchmarkAnalyzeNode(b *testing.B, pathName string) {
	var m1, m2 runtime.MemStats
	b.ResetTimer()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	//d := 1
	for i := 0; i < b.N; i++ {
		var err error
		path := "/Users/yili/node-scanning/demoV8"
		_, err = node.Analyze("testNode", path, node.AnalyzeOpts{false, true})
		require.NoError(b, err)
	}
	runtime.ReadMemStats(&m2)
	//fmt.Println("total:", m2.TotalAlloc-m1.TotalAlloc)
	fmt.Println("total:", m2.TotalAlloc-m1.TotalAlloc)

}
