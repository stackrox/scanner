package golang

import (
	"bytes"
	"fmt"

	"github.com/stackrox/scanner/pkg/analyzer/golang/internal/buildinfo"
	"github.com/stackrox/scanner/pkg/component"
)

func componentForModule(filePath string, mod *buildinfo.Module) *component.Component {
	comp := &component.Component{
		Name:       mod.Path,
		Version:    mod.Version,
		SourceType: component.GolangSourceType,
		Location:   filePath,
	}
	if mod.Replace != nil {
		if mod.Replace.Path == mod.Path {
			comp.Version = mod.Replace.Version
		} else {
			comp.Version = fmt.Sprintf("%s@%s", mod.Replace.Version, mod.Replace.Path)
		}
	}
	return comp
}

func analyzeGoBinary(filePath string, contents []byte) []*component.Component {
	bi, err := buildinfo.Read(bytes.NewReader(contents))
	if err != nil {
		return nil
	}

	var components []*component.Component
	components = append(components, &component.Component{
		Name:       "golang",
		Version:    bi.GoVersion,
		SourceType: component.GolangSourceType,
		Location:   filePath,
	})

	components = append(components, componentForModule(filePath, &bi.Main))
	for _, dep := range bi.Deps {
		components = append(components, componentForModule(filePath, dep))
	}
	return components
}
