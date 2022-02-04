package npm

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/component"
)

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

const function = "function"

var (
	functionBytes = []byte(function)
)

func parsePackageJSON(filePath string, fi os.FileInfo, contents io.ReaderAt) *component.Component {
	// If the prefix is a function, then we can ignore it as it will have a different package.json
	// that is actually in JSON format
	var functionHeader [len(function)]byte
	if _, err := contents.ReadAt(functionHeader[:], 0); err == nil && bytes.Equal(functionHeader[:], functionBytes) {
		return nil
	}
	var pkgJSON packageJSON
	err := json.NewDecoder(io.NewSectionReader(contents, 0, fi.Size())).Decode(&pkgJSON)
	if err != nil {
		logrus.Debugf("Couldn't unmarshal package.json file at %q: %v", filePath, err)
		return nil
	}

	if stringutils.AtLeastOneEmpty(pkgJSON.Name, pkgJSON.Version) {
		logrus.Debugf("Incomplete package.json file at %q; got %s/%s", filePath, pkgJSON.Name, pkgJSON.Version)
		return nil
	}
	return &component.Component{
		Name:       pkgJSON.Name,
		Version:    pkgJSON.Version,
		SourceType: component.NPMSourceType,
		Location:   filePath,
	}
}
