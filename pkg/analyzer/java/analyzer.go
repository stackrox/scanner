package java

import (
	"io"
	"os"
	"path/filepath"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
)

var knownIgnorePkgs = set.NewFrozenStringSet("rt", "root")

type analyzerImpl struct{}

func (analyzerImpl) ProcessFile(fullPath string, fi os.FileInfo, contents io.ReaderAt) []*component.Component {
	if !match(fullPath) || !fi.Mode().IsRegular() || fi.Size() == 0 {
		return nil
	}
	if !filterComponent(filepath.Base(fullPath)) {
		return nil
	}

	components := parseContents(fullPath, fi, contents)
	filteredComponents := components[:0]
	for _, c := range components {
		if knownIgnorePkgs.Contains(c.Name) {
			continue
		}
		addVersion(c)
		filteredComponents = append(filteredComponents, c)
	}
	return filteredComponents
}

func match(fullPath string) bool {
	return javaRegexp.MatchString(fullPath)
}

func addVersion(c *component.Component) {
	if c.JavaPkgMetadata == nil {
		return
	}
	c.Version = stringutils.FirstNonEmpty(c.JavaPkgMetadata.MavenVersion, c.JavaPkgMetadata.ImplementationVersion, c.JavaPkgMetadata.SpecificationVersion)
}

// Analyzer returns the Java analyzer.
func Analyzer() analyzer.Analyzer {
	return analyzerImpl{}
}
