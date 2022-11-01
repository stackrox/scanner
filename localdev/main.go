//nolint:revive
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stackrox/rox/pkg/utils"
	clair "github.com/stackrox/scanner"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/detection"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/singletons/requiredfilenames"

	// Register database driver.
	_ "github.com/stackrox/scanner/database/pgsql"

	// Register extensions.
	_ "github.com/stackrox/scanner/cpe/validation/all"
	_ "github.com/stackrox/scanner/ext/featurefmt/apk"
	_ "github.com/stackrox/scanner/ext/featurefmt/dpkg"
	_ "github.com/stackrox/scanner/ext/featurefmt/rpm"
	_ "github.com/stackrox/scanner/ext/featurens/alpinerelease"
	_ "github.com/stackrox/scanner/ext/featurens/aptsources"
	_ "github.com/stackrox/scanner/ext/featurens/busybox"
	_ "github.com/stackrox/scanner/ext/featurens/lsbrelease"
	_ "github.com/stackrox/scanner/ext/featurens/osrelease"
	_ "github.com/stackrox/scanner/ext/featurens/redhatrelease"
	_ "github.com/stackrox/scanner/ext/imagefmt/docker"
	_ "github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	_ "github.com/stackrox/scanner/ext/vulnsrc/alpine"
	_ "github.com/stackrox/scanner/ext/vulnsrc/amzn"
	_ "github.com/stackrox/scanner/ext/vulnsrc/debian"
	_ "github.com/stackrox/scanner/ext/vulnsrc/rhel"
	_ "github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
)

type manifestMatcher struct{}

func (m *manifestMatcher) Match(fullPath string, _ os.FileInfo, _ io.ReaderAt) (matches bool, extract bool) {
	return fullPath == "manifest.json" || strings.HasSuffix(fullPath, ".tar"), true
}

type Config struct {
	Layers []string
}

func filterComponentsByName(components []*component.Component, name string) []*component.Component {
	if name == "" {
		return components
	}
	filtered := components[:0]
	for _, c := range components {
		if strings.Contains(c.Name, name) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func analyzeLocalImage(path string) {
	fmt.Println(path)
	// Get local .tar.gz path
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	// Extract
	var matcher manifestMatcher
	analyzer.SetMaxExtractableFileSize(1024 * 1024 * 1024)
	analyzer.SetMaxELFExecutableFileSize(1024 * 1024 * 1024)
	filemap, err := tarutil.ExtractFiles(f, &matcher)
	if err != nil {
		panic(err)
	}

	if _, ok := filemap.Get("manifest.json"); !ok {
		panic("malformed .tar does not contain manifest.json")
	}

	var configs []Config
	fileData, _ := filemap.Get("manifest.json")
	if err := json.Unmarshal(fileData.Contents, &configs); err != nil {
		panic(err)
	}
	if len(configs) == 0 {
		panic("no configs found in tar")
	}
	config := configs[0]

	// detect namespace
	var namespace *database.Namespace
	for _, l := range config.Layers {
		fileData, _ = filemap.Get(l)
		layerTarReader := io.NopCloser(bytes.NewBuffer(fileData.Contents))
		files, err := imagefmt.ExtractFromReader(layerTarReader, "Docker", requiredfilenames.SingletonMatcher())
		if err != nil {
			panic(err)
		}
		namespace = detection.DetectNamespace(l, *files, nil, false)
		if namespace != nil {
			break
		}
	}
	fmt.Println(namespace)
	var total time.Duration
	var baseMap *tarutil.LayerFiles
	for _, l := range config.Layers {
		fileData, _ = filemap.Get(l)
		layerTarReader := io.NopCloser(bytes.NewBuffer(fileData.Contents))
		_, _, _, rhelv2Components, languageComponents, files, err := clair.DetectContentFromReader(layerTarReader, "Docker", l, &database.Layer{Namespace: namespace}, baseMap, false)
		baseMap = files
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		if rhelv2Components != nil {
			fmt.Printf("RHELv2 Components (%d): %s\n", len(rhelv2Components.Packages), rhelv2Components)
		}

		fmt.Printf("Removed components: %v\n", baseMap.GetRemovedFiles())

		languageComponents = filterComponentsByName(languageComponents, "")

		t := time.Now()
		features := cpe.CheckForVulnerabilities(l, languageComponents)

		sort.Slice(features, func(i, j int) bool {
			return features[i].Feature.Name < features[j].Feature.Name
		})

		total += time.Since(t)
		fmt.Printf("%s (%d components)\n", l, len(languageComponents))
		for _, f := range features {
			fmt.Println("\t", f.Feature.Name, f.Version, f.Feature.SourceType, f.Feature.Location, fmt.Sprintf("(%d vulns)", len(f.AffectedBy)))
			sort.Slice(f.AffectedBy, func(i, j int) bool {
				return f.AffectedBy[i].Name < f.AffectedBy[j].Name
			})
			for _, v := range f.AffectedBy {
				fmt.Println("\t\t", v.Name, v.FixedBy)
			}
		}
	}
	fmt.Printf("\n%0.4f seconds took Checking for vulns\n", total.Seconds())
}

// Assumes Working Directory is the repo's top-level directory (scanner/).
func main() {
	nvdtoolscache.BoltPath = "/tmp/temp.db"
	nvdPath, err := filepath.Abs("image/scanner/dump/nvd")
	if err != nil {
		panic(err)
	}
	utils.Must(os.Setenv("NVD_DEFINITIONS_DIR", nvdPath))
	nvdtoolscache.Singleton()

	path := "/Users/rtannenb/go/src/github.com/stackrox/scanner/local-images"

	fis, err := os.ReadDir(path)
	if err != nil {
		panic(err)
	}
	for _, fi := range fis {
		if fi.Name() != "ubuntu2204openssl.tar" {
			continue
		}
		analyzeLocalImage(filepath.Join(path, fi.Name()))
	}
}
