package nvdloader

import (
	"context"
	"io"

	"github.com/facebookincubator/nvdtools/vulndb"
	"github.com/pkg/errors"
	"github.com/stackrox/dotnet-scraper/types"
	"github.com/stackrox/scanner/pkg/gitarchive"
	"sigs.k8s.io/yaml"
)

const (
	nvdEnricherRepo = "https://github.com/stackrox/dotnet-scraper.git"
	nvdEnricherRef  = "main"
)

// FileFormatWrapper is a wrapper around .NET vulnerability file.
type FileFormatWrapper struct {
	LastUpdated string
	types.FileFormat
}

// Fetch fetches .NET and ASP.NET vulnerabilities from their source.
func Fetch() (map[string]*FileFormatWrapper, error) {
	ctx := context.Background()

	result, err := gitarchive.Fetch(ctx, gitarchive.FetchOptions{
		RepoURL: nvdEnricherRepo,
		Ref:     nvdEnricherRef,
	})
	if err != nil {
		return nil, errors.Wrap(err, "fetching dotnet-scraper archive")
	}
	defer result.Cleanup()

	// GitHub ZIPs have root directory: dotnet-scraper-main/
	resultMap := make(map[string]*FileFormatWrapper)

	for _, file := range result.ZipReader.File {
		if !isInDir(file.Name, "dotnet-scraper-main/cves") || !hasExtension(file.Name, ".yaml") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return nil, errors.Wrapf(err, "opening file: %v", file.Name)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "reading file: %v", file.Name)
		}

		var ff types.FileFormat
		if err := yaml.Unmarshal(data, &ff); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling file: %v", file.Name)
		}

		resultMap[ff.ID] = &FileFormatWrapper{
			LastUpdated: file.Modified.Format(vulndb.TimeLayout),
			FileFormat:  ff,
		}
	}

	return resultMap, nil
}

// isInDir checks if a file path is within a directory
func isInDir(path, dir string) bool {
	return len(path) > len(dir) && path[:len(dir)] == dir && path[len(dir)] == '/'
}

// hasExtension checks if a file path has the given extension
func hasExtension(path, ext string) bool {
	return len(path) > len(ext) && path[len(path)-len(ext):] == ext
}
