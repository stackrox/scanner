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

func parseJavaPackages(locationSoFar string, zipReader *zip.Reader) ([]*component.JavaPkgMetadata, error) {
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

	topLevelJavaPackage := component.JavaPkgMetadata{
		ImplementationVersion: manifest.implementationVersion,
		SpecificationVersion:  manifest.specificationVersion,
		Location:              locationSoFar,
		Name:                  fileName,
		Origin:                getOrigin(manifest),
	}

	allPackages := []*component.JavaPkgMetadata{&topLevelJavaPackage}

	for _, pomPropsF := range pomProperties {
		parsedPomProps, err := parseMavenPomProperties(pomPropsF)
		if err != nil {
			return nil, err
		}
		var currentJavaPackage *component.JavaPkgMetadata
		// The maven properties is for the same package as the manifest was.
		if strings.HasPrefix(fileName, parsedPomProps.artifactID) {
			currentJavaPackage = &topLevelJavaPackage
		} else {
			currentJavaPackage = new(component.JavaPkgMetadata)
			currentJavaPackage.Location = fmt.Sprintf("%s:%s", topLevelJavaPackage.Location, parsedPomProps.artifactID)
		}
		if parsedPomProps.groupID != "" {
			currentJavaPackage.Origin = parsedPomProps.groupID
		}
		if parsedPomProps.artifactID != "" {
			currentJavaPackage.Name = parsedPomProps.artifactID
		}
		currentJavaPackage.MavenVersion = parsedPomProps.version
		if currentJavaPackage != &topLevelJavaPackage {
			allPackages = append(allPackages, currentJavaPackage)
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
		allPackages = append(allPackages, subPackages...)
	}

	return allPackages, nil
}

func parseContents(locationSoFar string, contents []byte) ([]*component.JavaPkgMetadata, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return nil, err
	}
	return parseJavaPackages(locationSoFar, zipReader)
}
