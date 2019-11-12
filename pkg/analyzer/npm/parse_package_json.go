package npm

import (
	"bytes"
	"encoding/json"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/component"
)

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parsePackageJSON(filePath string, contents []byte) *component.Component {
	// If the prefix is a function, then we can ignore it as it will have a different package.json
	// that is actually in JSON format
	if bytes.HasPrefix(contents, []byte("function")) {
		return nil
	}
	var pkgJSON packageJSON
	err := json.Unmarshal(contents, &pkgJSON)
	if err != nil {
		logrus.Errorf("Couldn't unmarshal package.json file at %q: %v", filePath, err)
		return nil
	}

	if stringutils.AtLeastOneEmpty(pkgJSON.Name, pkgJSON.Version) {
		logrus.Errorf("Incomplete package.json file at %q; got %s/%s", filePath, pkgJSON.Name, pkgJSON.Version)
		return nil
	}
	return &component.Component{
		Name:       pkgJSON.Name,
		Version:    pkgJSON.Version,
		SourceType: component.NPMSourceType,
		Location:   filePath,
	}
}
