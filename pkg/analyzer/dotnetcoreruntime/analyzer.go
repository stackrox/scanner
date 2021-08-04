package dotnetcoreruntime

import (
	"os"
	"regexp"
	"strings"

	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

var (
	// dotNetCorePattern is the common directory pattern used to detect .NET Core runtimes.
	// This pattern was conceived based on observation and experimentation in various Linux containers.
	//
	// The experiments were run via the `dotnet --info` command. This command outputs detected .NET Core runtimes.
	// It was found that any directory under the container's `dotnet/shared/` directory with a subdirectory that is a
	// semantic version suffices as a .NET Core runtime for `dotnet --info`.
	//
	// For example:
	// /usr/share/dotnet/shared/Hello/1.2.3 in a Debian container made `dotnet --info` think
	// there is a runtime called Hello with version 1.2.3.
	//
	// It did not work for /usr/share/dotnet/shared/Hello/1.2, as this example is missing the patch version
	// in the semantic versioning scheme.
	//
	dotNetCorePattern = regexp.MustCompile(`^.*/dotnet/shared/(Microsoft\.(?:AspNet|NET)Core\.(?:App|All))/([0-9]+\.[0-9]+\.[0-9]+)/$`)
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) (match bool, extract bool) {
	return fileInfo.IsDir() && dotNetCorePattern.MatchString(fullPath), false
}

func matchRegex(path string) bool {
	return dotNetCorePattern.MatchString(path)
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var allComponents []*component.Component
	for filePath := range fileMap {
		if !matchRegex(filePath) {
			continue
		}
		if c := parseMetadata(filePath); c != nil {
			allComponents = append(allComponents, c)
		}
	}
	return allComponents, nil
}

// parseMetadata gets all of the necessary information from the directory path.
// Observation and experimentation showed that the `dotnet` CLI detects runtimes solely based on the
// directory path.
// This function assumes filePath matches `dotNetCorePattern`.
func parseMetadata(filePath string) *component.Component {
	// This should be a slice of length 3.
	// [<Full match> Microsoft.(AspNet|NET)Core.(App|All) <Semantic version>]
	match := dotNetCorePattern.FindStringSubmatch(filePath)
	return &component.Component{
		Location:   filePath,
		SourceType: component.DotNetCoreRuntimeSourceType,
		Name:       strings.ToLower(match[1]),
		Version:    match[2],
	}
}

// Analyzer returns a .NET analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
