package nvdloader

import (
	"github.com/stackrox/dotnet-scraper/types"
)

// FileFormatWrapper is a wrapper around .NET vulnerability file.
type FileFormatWrapper struct {
	LastUpdated string
	types.FileFormat
}
