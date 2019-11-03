package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/singletons/requiredfilenames"

	// Register database driver.
	_ "github.com/stackrox/scanner/database/pgsql"

	// Register extensions.
	_ "github.com/stackrox/scanner/ext/featurefmt/apk"
	_ "github.com/stackrox/scanner/ext/featurefmt/dpkg"
	_ "github.com/stackrox/scanner/ext/featurefmt/rpm"
	_ "github.com/stackrox/scanner/ext/featurens/alpinerelease"
	_ "github.com/stackrox/scanner/ext/featurens/aptsources"
	_ "github.com/stackrox/scanner/ext/featurens/lsbrelease"
	_ "github.com/stackrox/scanner/ext/featurens/osrelease"
	_ "github.com/stackrox/scanner/ext/featurens/redhatrelease"
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
	_ "github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	_ "github.com/stackrox/scanner/ext/vulnsrc/alpine"
	_ "github.com/stackrox/scanner/ext/vulnsrc/amzn"
	_ "github.com/stackrox/scanner/ext/vulnsrc/debian"
	_ "github.com/stackrox/scanner/ext/vulnsrc/oracle"
	_ "github.com/stackrox/scanner/ext/vulnsrc/rhel"
	_ "github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
)

type manifestMatcher struct{}

func (m *manifestMatcher) Match(fullPath string, fileInfo os.FileInfo) bool {
	return fullPath == "manifest.json" || strings.HasSuffix(fullPath, ".tar")
}

type Config struct {
	Layers []string
}

func main() {
	// Need to export NVD_DEFINITIONS_DIR in order to get vulnerabilities

	// Get local .tar.gz
	f, err := os.Open("/Users/connorgorman/repos/src/github.com/stackrox/scanner/vulns/python/struts.tar.gz")
	if err != nil {
		panic(err)
	}

	// Extract
	var matcher manifestMatcher
	filemap, err := tarutil.ExtractFiles(f, &matcher)
	if err != nil {
		panic(err)
	}

	if _, ok := filemap["manifest.json"]; !ok {
		panic("malformed .tar does not contain manifest.json")
	}

	var configs []Config
	if err := json.Unmarshal(filemap["manifest.json"], &configs); err != nil {
		panic(err)
	}
	if len(configs) == 0 {
		panic("no configs found in tar")
	}
	config := configs[0]

	// detect namespace
	var namespace *database.Namespace
	for _, l := range config.Layers {
		layerTarReader := ioutil.NopCloser(bytes.NewBuffer(filemap[l]))
		files, err := imagefmt.ExtractFromReader(layerTarReader, "Docker", requiredfilenames.SingletonMatcher())
		if err != nil {
			panic(err)
		}
		namespace, err = clair.DetectNamespace(l, files, nil)
		if err != nil {
			panic(err)
		}
		if namespace != nil {
			break
		}
	}
	for _, l := range config.Layers {
		layerTarReader := ioutil.NopCloser(bytes.NewBuffer(filemap[l]))
		_, _, languageComponents, err := clair.DetectContentFromReader(layerTarReader, "Docker", l, &database.Layer{Namespace: namespace})
		if err != nil {
			panic(err)
		}

		features := cpe.CheckForVulnerabilities(l, languageComponents)
		fmt.Println(l)
		for _, f := range features {
			fmt.Println("\t", f.Feature.Name, f.Version)
			for _, v := range f.AffectedBy {
				fmt.Println("\t\t", v.Name)
			}
		}
	}
}
