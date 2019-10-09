package driver

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stackrox/scanner/pkg/analyzers"
	"github.com/stackrox/scanner/pkg/analyzers/java"
	"github.com/stackrox/scanner/pkg/analyzers/simple"
	"github.com/stackrox/scanner/pkg/extractors"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeLayerWithExtractor(t *testing.T) {
	const dir = "/Users/viswa/Google Drive/anchore/analysis_scratch/17a230c2-6f8b-40a4-9605-b06cf70d4a04/raw/blobs/sha256"
	files, err := ioutil.ReadDir(dir)
	require.NoError(t, err)

	for _, fileInfo := range files {
		if fileInfo.IsDir() || len(fileInfo.Name()) != 64 {
			continue
		}
		f, err := os.Open(filepath.Join(dir, fileInfo.Name()))
		require.NoError(t, err)
		components, err := AnalyzeLayerWithExtractor(f, extractors.DockerExtractor{}, []analyzers.Analyzer{simple.Analyzer{}, java.Analyzer{}})
		require.NoError(t, err)
		fmt.Printf("Filename: %s\nComponents: %s\n\n", fileInfo.Name(), spew.Sdump(components))
	}
}
