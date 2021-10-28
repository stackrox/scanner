package analyzer

import (
	"io"
	"os"

	"github.com/stackrox/scanner/pkg/component"
)

// Analyzer defines the functions for analyzing images and extracting the components present in them.
type Analyzer interface {
	ProcessFile(filePath string, fi os.FileInfo, contents io.ReaderAt) []*component.Component
}
