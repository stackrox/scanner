package analyzer

import (
	"io"
	"os"

	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/elf"
)

// Analyzer defines the functions for analyzing images and extracting the components present in them.
type Analyzer interface {
	ProcessFile(filePath string, fi os.FileInfo, contents io.ReaderAt) []*component.Component
}

// Files stores information on a sub-set of files being analyzed from an image.
// It provides methods to retrieve information from individual files, or list
// them based on some prefix.
type Files interface {

	// Get returns the data about a file if it exists, otherwise set exists to false.
	Get(path string) (data FileData, exists bool)

	// GetFilesPrefix returns a map of files matching the specified prefix, empty map
	// if none found. The prefix itself is not matched.
	GetFilesPrefix(prefix string) (filesMap map[string]FileData)
}

// FileData is the contents of a file and relevant metadata.
type FileData struct {
	// Contents is the contents of the file.
	Contents []byte

	// Executable indicates if the file is executable.
	Executable bool

	// ELFMetadata contains the dynamic library dependency metadata if the file is in ELF format.
	ELFMetadata *elf.Metadata
}
