package java

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	javaRegexp = regexp.MustCompile(`^.*\.([jwe]ar|[jh]pi)$`)
)

func getOrigin(mf parsedManifestMF) string {
	if mf.specificationVendor != "" {
		return mf.specificationVendor
	}
	return mf.implementationVendor
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

	manifest, err := parseManifestMF(manifestFile)
	if err != nil {
		log.Debugf("error parsing java manifest file: %v", err)
		return nil, nil
	}

	fileNameWithExtension := locationSoFar[strings.LastIndex(locationSoFar, "/")+1:]
	fileName := strings.TrimSuffix(fileNameWithExtension, filepath.Ext(fileNameWithExtension))

	topLevelComponent := newJavaComponent(locationSoFar)
	topLevelComponent.Name = fileName
	topLevelComponent.JavaPkgMetadata = &component.JavaPkgMetadata{
		ImplementationVersion: manifest.implementationVersion,
		SpecificationVersion:  manifest.specificationVersion,
		Origin:                getOrigin(manifest),
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
			currentComponent.JavaPkgMetadata.Origin = parsedPomProps.groupID
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

		reader, err := subArchiveF.Open()
		if err != nil {
			log.Debugf("error opening java sub archive: %v", err)
			continue
		}
		contents, err := ioutil.ReadAll(reader)
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
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return nil, err
	}
	return parseComponentsFromZipReader(locationSoFar, zipReader)
}
