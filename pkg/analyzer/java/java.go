package java

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/ioutils"
)

var (
	javaRegexp = regexp.MustCompile(`^.*\.([jwe]ar|[jh]pi)$`)

	filteredJavaComponents = []string{
		"annotation",
		"spec",
	}
)

///////////////////////////////////////////////////
// BEGIN
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

// nameRegexp is used to attempt to pull a name and version out of a jar's
// filename.
var nameRegexp = regexp.MustCompile(`([[:graph:]]+)-([[:digit:]][\-.[:alnum:]]*(?:-SNAPSHOT)?)`)

// checkName returns the extracted package name from the above regexp.
func checkName(name string) string {
	m := nameRegexp.FindStringSubmatch(name)
	if len(m) < 2 {
		return name
	}
	return m[1]
}

///////////////////////////////////////////////////
// END
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

// Filter some substrings: e.g. annotations and specs can be ignored for example
func filterComponent(component string) bool {
	for _, filteredSubstring := range filteredJavaComponents {
		if strings.Contains(component, filteredSubstring) {
			return true
		}
	}
	return false
}

func getOrigins(mf parsedManifestMF) []string {
	var origins []string
	for _, s := range []string{mf.implementationVendorID, mf.specificationVendor, mf.implementationVendor, mf.bundleSymbolicName} {
		if s != "" {
			origins = append(origins, s)
		}
	}
	return origins
}

func newJavaComponent(location string) component.Component {
	return component.Component{
		SourceType:      component.JavaSourceType,
		Location:        location,
		JavaPkgMetadata: &component.JavaPkgMetadata{},
	}
}

func parseComponentsFromZipReader(locationSoFar string, zipReader *zip.Reader) []*component.Component {
	var manifestFile *zip.File
	var subArchives []*zip.File
	var pomProperties []*zip.File
	for _, f := range zipReader.File {
		switch {
		case f.Name == manifestFileName:
			manifestFile = f
		case javaRegexp.MatchString(f.Name):
			subArchives = append(subArchives, f)
		case strings.HasSuffix(f.Name, "/pom.properties"):
			pomProperties = append(pomProperties, f)
		}
	}

	if manifestFile == nil {
		return nil
	}

	manifest, err := parseManifestMF(locationSoFar, manifestFile)
	if err != nil {
		log.Debugf("error parsing java manifest file: %v", err)
		return nil
	}

	fileName := strings.TrimSuffix(filepath.Base(locationSoFar), filepath.Ext(locationSoFar))

	topLevelComponent := newJavaComponent(locationSoFar)
	topLevelComponent.Name = checkName(fileName)
	topLevelComponent.JavaPkgMetadata = &component.JavaPkgMetadata{
		ImplementationVersion: manifest.implementationVersion,
		SpecificationVersion:  manifest.specificationVersion,
		Origins:               getOrigins(manifest),
		BundleName:            manifest.bundleName,
	}

	allComponents := []*component.Component{&topLevelComponent}
	for _, pomPropsF := range pomProperties {
		parsedPomProps, err := parseMavenPomProperties(pomPropsF)
		if err != nil {
			log.Debugf("error parsing maven pom properties of java sub archive: %v", err)
			continue
		}
		var currentComponent *component.Component
		// The maven properties is for the same package as the manifest was.
		if strings.HasPrefix(fileName, parsedPomProps.artifactID) {
			currentComponent = &topLevelComponent
		} else {
			newComponent := newJavaComponent(fmt.Sprintf("%s:%s", topLevelComponent.Location, parsedPomProps.artifactID))
			currentComponent = &newComponent
		}
		if parsedPomProps.groupID != "" {
			currentComponent.JavaPkgMetadata.Origins = append(currentComponent.JavaPkgMetadata.Origins, parsedPomProps.groupID)
		}
		if parsedPomProps.artifactID != "" {
			currentComponent.Name = parsedPomProps.artifactID
		}
		currentComponent.JavaPkgMetadata.MavenVersion = parsedPomProps.version
		if currentComponent != &topLevelComponent {
			allComponents = append(allComponents, currentComponent)
		}
	}

	var buf []byte
	for _, subArchiveF := range subArchives {
		if subArchiveF.CompressedSize64 == 0 {
			continue
		}
		if filterComponent(subArchiveF.Name) {
			continue
		}

		reader, err := subArchiveF.Open()
		if err != nil {
			log.Debugf("error opening java sub archive: %v", err)
			continue
		}

		fi := subArchiveF.FileInfo()
		contents := ioutils.NewLazyReaderAtWithBuffer(reader, fi.Size(), buf)

		subComponents := parseContents(fmt.Sprintf("%s:%s", locationSoFar, subArchiveF.Name), fi, contents)
		allComponents = append(allComponents, subComponents...)
		buf = contents.StealBuffer()
	}

	return allComponents
}

func parseContents(locationSoFar string, fi os.FileInfo, contents io.ReaderAt) []*component.Component {
	// Typically, this is when a jar has a prefix of ._
	zipReader, err := zip.NewReader(contents, fi.Size())
	if err != nil {
		log.Debugf("error parsing %q: %v", locationSoFar, err)
		return nil
	}
	return parseComponentsFromZipReader(locationSoFar, zipReader)
}
