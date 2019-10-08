package java

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"regexp"

	"github.com/stackrox/scanner/pkg/filemap"
	"github.com/stackrox/scanner/pkg/types"
)

var (
	javaRegexp = regexp.MustCompile(`^.*\.([jwe]ar|[jh]pi)$`)
)

type javaPackages struct {
	typ    string
	origin string
}

func parseJavaPackages(zipReader *zip.Reader) error {
}

func parseContents(contents []byte) error {
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return err
	}
	return parseJavaPackages(zipReader)
}

type Analyzer struct{}

func (a Analyzer) Match(filePath string) bool {
	return javaRegexp.MatchString(filepath.Base(filePath))
}

func (a Analyzer) Extract(fileMap filemap.FileMap) ([]types.Component, error) {
	for filePath, contents := range fileMap {
		if !a.Match(filePath) {
			continue
		}
	}
}
