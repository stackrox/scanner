package java

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

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

func parseJavaPackages(locationSoFar string, zipReader *zip.Reader) ([]*component.Component, error) {
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
		// TODO(viswa): Make this more forgiving.
		return nil, errors.New("no manifest file found")
	}

	manifest, err := parseManifestMF(manifestFile)
	if err != nil {
		return nil, err
	}

	fileNameWithExtension := locationSoFar[strings.LastIndex(locationSoFar, "/")+1:]
	fileName := strings.TrimSuffix(fileNameWithExtension, filepath.Ext(fileNameWithExtension))

	topLevelComponent := component.Component{
		Location: locationSoFar,
		JavaPkgMetadata: &component.JavaPkgMetadata{
			ImplementationVersion: manifest.implementationVersion,
			SpecificationVersion:  manifest.specificationVersion,
			Name:                  fileName,
			Origin:                getOrigin(manifest),
		},
	}

	allComponents := []*component.Component{&topLevelComponent}

	for _, pomPropsF := range pomProperties {
		parsedPomProps, err := parseMavenPomProperties(pomPropsF)
		if err != nil {
			return nil, err
		}
		var currentComponent *component.Component
		// The maven properties is for the same package as the manifest was.
		if strings.HasPrefix(fileName, parsedPomProps.artifactID) {
			currentComponent = &topLevelComponent
		} else {
			currentComponent = &component.Component{
				Location:        fmt.Sprintf("%s:%s", topLevelComponent.Location, parsedPomProps.artifactID),
				JavaPkgMetadata: &component.JavaPkgMetadata{},
			}
		}
		if parsedPomProps.groupID != "" {
			currentComponent.JavaPkgMetadata.Origin = parsedPomProps.groupID
		}
		if parsedPomProps.artifactID != "" {
			currentComponent.JavaPkgMetadata.Name = parsedPomProps.artifactID
		}
		currentComponent.JavaPkgMetadata.MavenVersion = parsedPomProps.version
		if currentComponent != &topLevelComponent {
			allComponents = append(allComponents, currentComponent)
		}
	}

	for _, subArchiveF := range subArchives {
		reader, err := subArchiveF.Open()
		if err != nil {
			return nil, err
		}
		contents, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}

		subPackages, err := parseContents(fmt.Sprintf("%s:%s", locationSoFar, subArchiveF.Name), contents)
		if err != nil {
			return nil, err
		}
		allComponents = append(allComponents, subPackages...)
	}

	return allComponents, nil
}

func parseContents(locationSoFar string, contents []byte) ([]*component.Component, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return nil, err
	}
	return parseJavaPackages(locationSoFar, zipReader)
}
