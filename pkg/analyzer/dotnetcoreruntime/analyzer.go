package dotnetcoreruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/dotnet"
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
	dotNetPrefix      = regexp.MustCompile(`^.*/dotnet/shared/.*$`)
)

type analyzerImpl struct{}

func (a analyzerImpl) Match(fullPath string, fileInfo os.FileInfo) bool {
	if fileInfo.IsDir() && dotNetCorePattern.MatchString(fullPath) {
		return true
	}
	if dotnet.DLLPattern.MatchString(fullPath) {
		return true
	}
	return dotNetPrefix.MatchString(fullPath) && strings.HasSuffix(fullPath, "deps.json")
}

func matchRegex(path string) bool {
	if dotNetCorePattern.MatchString(path) {
		return true
	}
	return dotNetPrefix.MatchString(path) && strings.HasSuffix(path, "deps.json")
}

func (a analyzerImpl) Analyze(fileMap tarutil.FilesMap) ([]*component.Component, error) {
	var allComponents []*component.Component
	for filePath, contents := range fileMap {
		if !matchRegex(filePath) {
			continue
		}
		if len(contents) == 0 {
			if c := parseMetadata(filePath); c != nil {
				allComponents = append(allComponents, c)
			}
			continue
		}
		allComponents = append(allComponents, parseDepsFile(fileMap, contents)...)
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

func parseDepsFile(fileMap tarutil.FilesMap, file []byte) []*component.Component {
	var m map[string]interface{}
	if err := json.Unmarshal(file, &m); err != nil {
		logrus.Error(err)
		return nil
	}

	dllToLocationMap := make(map[string]string)
	for filePath := range fileMap {
		if filepath.Ext(filePath) == ".dll" {
			dllToLocationMap[filepath.Base(filePath)] = filePath
		}
	}

	components := make([]*component.Component, 0)
	getAllDLLComponentsRecursively(m, dllToLocationMap, &components)
	return components
}

func getAllDLLComponentsRecursively(m map[string]interface{}, dllToLocationMap map[string]string, comps *[]*component.Component) {
	for k, v := range m {
		subMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if filepath.Ext(k) == ".dll" {
			baseName := filepath.Base(k)
			name := strings.TrimSuffix(baseName, ".dll")
			versionI := subMap["assemblyVersion"]
			version, ok := versionI.(string)
			if !ok {
				continue
			}
			*comps = append(*comps, &component.Component{
				Name:       strings.ToLower(name),
				Version:    version,
				SourceType: component.DotNetCoreRuntimeSourceType,
				Location:   dllToLocationMap[baseName],
			})
			continue
		}
		getAllDLLComponentsRecursively(subMap, dllToLocationMap, comps)
	}
}

func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
