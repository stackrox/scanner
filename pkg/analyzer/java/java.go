package java

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	javaRegexp = regexp.MustCompile(`^.*\.([jwe]ar|[jh]pi)$`)

	filteredJavaComponents = []string{
		"annotation",
		"spec",
	}
)

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

func parseComponentsFromZipReader(locationSoFar string, zipReader *zip.Reader) ([]*component.Component, error) {
	var manifestFile *zip.File
	var subArchives []*zip.File
	var pomProperties []*zip.File
	for _, f := range zipReader.File {
		if f.Name == manifestFileName {
			manifestFile = f
		} else if javaRegexp.MatchString(f.Name) {
			subArchives = append(subArchives, f)
		} else if strings.HasSuffix(f.Name, "/pom.properties") {
			pomProperties = append(pomProperties, f)
		}
	}

	if manifestFile == nil {
		return nil, nil
	}

	manifest, err := parseManifestMF(locationSoFar, manifestFile)
	if err != nil {
		log.Debugf("error parsing java manifest file: %v", err)
		return nil, nil
	}

	fileName := strings.TrimSuffix(filepath.Base(locationSoFar), filepath.Ext(locationSoFar))

	topLevelComponent := newJavaComponent(locationSoFar)
	topLevelComponent.Name = fileName
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
		contents, err := io.ReadAll(reader)
		if err != nil {
			log.Debugf("error reading java sub archive: %v", err)
			continue
		}

		subComponents, err := parseContents(fmt.Sprintf("%s:%s", locationSoFar, subArchiveF.Name), contents)
		if err != nil {
			log.Debugf("error parsing contents of java sub archive: %v", err)
			continue
		}
		allComponents = append(allComponents, subComponents...)
	}

	return allComponents, nil
}

func parseContents(locationSoFar string, contents []byte) ([]*component.Component, error) {
	// Typically, this is when a jar has a prefix of ._
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		log.Debugf("error parsing %q: %v", locationSoFar, err)
		return nil, nil
	}
	return parseComponentsFromZipReader(locationSoFar, zipReader)
}
