package dotnetcoreruntime

import (
	"os"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/internal/common"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

var (
	// dotNetCorePattern is the common directory pattern used to detect .NET Core runtimes.
	// This pattern was conceived based on observation and experimentation in various Linux containers.
	// TODO: Consider Microsoft.AspNetCore.All?
	dotNetCorePattern = regexp.MustCompile(`^.*/dotnet/shared/Microsoft\.(AspNet|NET)Core\.App/[0-9]+\.[0-9]+\.[0-9]+/$`)
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) bool {
	if !fileInfo.IsDir() {
		return false
	}

	return matchRegex(fullPath)
}

func matchRegex(path string) bool {
	return dotNetCorePattern.MatchString(path)
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	return common.ExtractComponents(fileMap, matchRegex, parseMetadata), nil
}

// parseMetadata gets all of the necessary information from the directory path.
// Observation and experimentation showed that the `dotnet` CLI detects runtimes solely based on the
// directory path.
func parseMetadata(filePath string, _ []byte) *component.Component {
	// Based on dotNetCorePattern, we know we will find the version in the second to last index
	// and the name in the third to last index (the last will be blank).
	dirs := strings.Split(filePath, "/")
	name := dirs[len(dirs)-3]
	version := dirs[len(dirs)-2]
	return &component.Component{
		Location:   filePath,
		SourceType: component.DotNetCoreRuntimeSourceType,
		Name:       name,
		Version:    version,
	}
}

func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
