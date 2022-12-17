package v1

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupeVersionMatcher(t *testing.T) {
	cases := []struct {
		v1, v2   string
		expected bool
	}{
		{
			v1:       "diff1",
			v2:       "diff2",
			expected: false,
		},
		{
			v1:       "3.5.13",
			v2:       "3.5.13",
			expected: true,
		},
		{
			v1:       "3.5.13",
			v2:       "3.5.13-1",
			expected: true,
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.v1, c.v2), func(t *testing.T) {
			assert.Equal(t, c.expected, dedupeVersionMatcher(c.v1, c.v2))
		})
	}
}

func TestShouldDedupeLanguageFeature(t *testing.T) {
	cases := []struct {
		name       string
		feature    Feature
		osFeatures []Feature
		dedupe     bool
	}{
		{
			name: "jinja-individual",
			feature: Feature{
				Name:          "jinja2",
				VersionFormat: "Python",
				Version:       "2.10",
			},
			dedupe: false,
		},
		{
			name: "jinja-duplicate",
			feature: Feature{
				Name:          "jinja2",
				VersionFormat: "Python",
				Version:       "2.10",
			},
			osFeatures: []Feature{
				{
					Name:          "jinja2",
					VersionFormat: "dpkg",
					Version:       "2.10-2",
				},
			},
			dedupe: true,
		},
		{
			name: "python-werkzeug",
			feature: Feature{
				Name:          "werkzeug",
				VersionFormat: component.PythonSourceType.String(),
				Version:       "0.14.1",
			},
			osFeatures: []Feature{
				{
					Name:          "python-werkzeug",
					VersionFormat: "dpkg",
					Version:       "0.14.1+dfsg1-4",
				},
			},
			dedupe: true,
		},
		{
			name: "libsass",
			feature: Feature{
				Name:          "libsass",
				VersionFormat: component.PythonSourceType.String(),
				Version:       "0.17.1",
			},
			osFeatures: []Feature{
				{
					Name:          "libsass-python",
					VersionFormat: "dpkg",
					Version:       "0.17.1-1",
				},
			},
			dedupe: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.dedupe, shouldDedupeLanguageFeature(c.feature, c.osFeatures))
		})
	}
}

func TestLatestLanguageFeatureVersion(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	t.Setenv("NVD_DEFINITIONS_DIR", defsDir)

	prevBoltPath := nvdtoolscache.BoltPath
	defer func() {
		nvdtoolscache.BoltPath = prevBoltPath
	}()

	dir, err := os.MkdirTemp("", "bolt")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	nvdtoolscache.BoltPath = filepath.Join(dir, "temp.db")

	db := newMockDatastore()
	db.layers["layer"] = []*component.LayerToComponents{
		{
			Layer: "layer",
			Components: []*component.Component{
				{
					SourceType:      component.JavaSourceType,
					Name:            "struts",
					Version:         "2.3.12",
					Location:        "usr/local/tomcat/webapps/ROOT.war:WEB-INF/lib/struts2-core2.3.12.jar",
					JavaPkgMetadata: &component.JavaPkgMetadata{},
				},
			},
		},
	}
	dbLayer := &Layer{
		Name: "layer",
	}

	addLanguageVulns(db, dbLayer, "", false)
	assert.Equal(t, "2.3.29", dbLayer.Features[0].FixedBy)
}

func TestAddLanguageVulns(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	t.Setenv("NVD_DEFINITIONS_DIR", defsDir)

	prevBoltPath := nvdtoolscache.BoltPath
	defer func() {
		nvdtoolscache.BoltPath = prevBoltPath
	}()

	dir, err := os.MkdirTemp("", "bolt")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	nvdtoolscache.BoltPath = filepath.Join(dir, "temp.db")

	db := makeTestDB()

	layer := &Layer{
		Name: "layer2",
	}
	addLanguageVulns(db, layer, "", false)
	assert.Len(t, layer.Features, 1)
	feature := layer.Features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Len(t, feature.Vulnerabilities, 1)
	assert.Equal(t, "layer2", feature.AddedBy)
	vuln := feature.Vulnerabilities[0]
	assert.Equal(t, "CVE-2020-123123123", vuln.Name)

	layer = &Layer{
		Name: "layer3",
	}
	addLanguageVulns(db, layer, "", false)
	assert.Len(t, layer.Features, 2)

	layer = &Layer{
		Name: "layer4",
	}
	addLanguageVulns(db, layer, "", false)
	assert.Empty(t, layer.Features)

	layer = &Layer{
		Name: "layer6",
	}
	addLanguageVulns(db, layer, "", false)
	assert.Len(t, layer.Features, 1)
	feature = layer.Features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Equal(t, "layer5", feature.AddedBy)

	layer = &Layer{
		Name: "layer8",
	}
	addLanguageVulns(db, layer, "", false)
	assert.Empty(t, layer.Features)
}

func TestGetLanguageComponents(t *testing.T) {
	// This should have similar results as TestAddLanguageVulns.
	// The component duplicates are not filtered, and vulnerabilities are not included.

	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	t.Setenv("NVD_DEFINITIONS_DIR", defsDir)

	prevBoltPath := nvdtoolscache.BoltPath
	defer func() {
		nvdtoolscache.BoltPath = prevBoltPath
	}()

	dir, err := os.MkdirTemp("", "bolt")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	nvdtoolscache.BoltPath = filepath.Join(dir, "temp.db")

	db := makeTestDB()

	components := getLanguageComponents(db, "layer2", "", false)
	assert.NotNil(t, components)
	assert.Len(t, components, 1)
	c := components[0]
	assert.Equal(t, "microsoft.dotnetcore.app", c.Name)
	assert.Equal(t, "3.2.0", c.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", c.Location)
	assert.Equal(t, "layer2", c.AddedBy)

	components = getLanguageComponents(db, "layer3", "", false)
	assert.NotNil(t, components)
	assert.Len(t, components, 2)

	components = getLanguageComponents(db, "layer4", "", false)
	assert.Empty(t, components)

	components = getLanguageComponents(db, "layer6", "", false)
	assert.NotNil(t, components)
	// We do not filter out the components.
	// Instead, this is saved for the vulnerability matching step.
	assert.Len(t, components, 2)
	c = components[0]
	assert.Equal(t, "microsoft.dotnetcore.app", c.Name)
	assert.Equal(t, "3.2.0", c.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", c.Location)
	assert.Equal(t, "layer6", c.AddedBy)
	c = components[1]
	assert.Equal(t, "microsoft.dotnetcore.app", c.Name)
	assert.Equal(t, "3.2.0", c.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", c.Location)
	assert.Equal(t, "layer5", c.AddedBy)

	components = getLanguageComponents(db, "layer8", "", false)
	assert.Empty(t, components)
}

func TestGetLanguageFeatures(t *testing.T) {
	// This should give the same results as TestAddLanguageVulns.

	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	t.Setenv("NVD_DEFINITIONS_DIR", defsDir)

	prevBoltPath := nvdtoolscache.BoltPath
	defer func() {
		nvdtoolscache.BoltPath = prevBoltPath
	}()

	dir, err := os.MkdirTemp("", "bolt")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	nvdtoolscache.BoltPath = filepath.Join(dir, "temp.db")

	db := makeTestDB()

	components := getLanguageComponents(db, "layer2", "", false)
	features, err := getLanguageFeatures(nil, convert.LanguageComponents(components), false)
	assert.NoError(t, err)
	assert.Len(t, features, 1)
	feature := features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Equal(t, "layer2", feature.AddedBy)

	components = getLanguageComponents(db, "layer3", "", false)
	features, err = getLanguageFeatures(nil, convert.LanguageComponents(components), false)
	assert.NoError(t, err)
	assert.Len(t, features, 2)

	components = getLanguageComponents(db, "layer4", "", false)
	features, err = getLanguageFeatures(nil, convert.LanguageComponents(components), false)
	assert.NoError(t, err)
	assert.Empty(t, features)

	components = getLanguageComponents(db, "layer6", "", false)
	features, err = getLanguageFeatures(nil, convert.LanguageComponents(components), false)
	assert.NoError(t, err)
	assert.Len(t, features, 1)
	feature = features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Equal(t, "layer5", feature.AddedBy)

	components = getLanguageComponents(db, "layer8", "", false)
	features, err = getLanguageFeatures(nil, convert.LanguageComponents(components), false)
	assert.NoError(t, err)
	assert.Empty(t, features)
}

func makeTestDB() database.Datastore {
	db := newMockDatastore()
	// 2 layers. First layer's features are deleted in the 2nd layer. 2nd layer adds a new feature.
	db.layers["layer2"] = []*component.LayerToComponents{
		{
			Layer: "layer1",
			Components: []*component.Component{
				{
					SourceType: component.DotNetCoreRuntimeSourceType,
					Name:       "microsoft.dotnetcore.app",
					Version:    "3.1.2",
					Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.2/",
				},
			},
		},
		{
			Layer: "layer2",
			Components: []*component.Component{
				{
					SourceType: component.DotNetCoreRuntimeSourceType,
					Name:       "microsoft.dotnetcore.app",
					Version:    "3.2.0",
					Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/",
				},
			},
			Removed: []string{"usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.2/"},
		},
	}
	// 2 layers. First layer's features are removed in the second. All features from the same file.
	layer4 := []*component.LayerToComponents{
		{
			Layer: "layer3",
			Components: []*component.Component{
				{
					SourceType:      component.JavaSourceType,
					Name:            "zookeeper",
					Version:         "3.4.13",
					Location:        "zookeeper-3.4.13/contrib/fatjar/zookeeper-3.4.13-fatjar.jar",
					JavaPkgMetadata: &component.JavaPkgMetadata{},
				},
				{
					SourceType: component.JavaSourceType,
					Name:       "guava",
					Version:    "18.0",
					Location:   "zookeeper-3.4.13/contrib/fatjar/zookeeper-3.4.13-fatjar.jar:guava",
					JavaPkgMetadata: &component.JavaPkgMetadata{
						Origins: []string{"google"},
					},
				},
			},
		},
		{
			Layer:      "layer4",
			Components: []*component.Component{},
			Removed:    []string{"zookeeper-3.4.13/contrib/fatjar/zookeeper-3.4.13-fatjar.jar"},
		},
	}
	db.layers["layer3"] = layer4[:1]
	db.layers["layer4"] = layer4
	// 2 layers. 2nd layer symbolizes a chown or touch to the file. AddedBy should be the first layer.
	db.layers["layer6"] = []*component.LayerToComponents{
		{
			Layer: "layer5",
			Components: []*component.Component{
				{
					SourceType: component.DotNetCoreRuntimeSourceType,
					Name:       "microsoft.dotnetcore.app",
					Version:    "3.2.0",
					Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/",
				},
			},
		},
		{
			Layer: "layer6",
			Components: []*component.Component{
				{
					SourceType: component.DotNetCoreRuntimeSourceType,
					Name:       "microsoft.dotnetcore.app",
					Version:    "3.2.0",
					Location:   "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/",
				},
			},
		},
	}
	// Simplified version of real image seen in the wild.
	db.layers["layer8"] = []*component.LayerToComponents{
		{
			Layer: "layer7",
			Components: []*component.Component{
				{
					SourceType: component.NPMSourceType,
					Name:       "websocket-extensions",
					Version:    "0.1.3",
					Location:   "usr/local/share/.cache/yarn/v4/npm-websocket-extensions-0.1.3-5d2ff22977003ec687a4b87073dfbbac146ccf29/node_modules/websocket-extensions/package.json",
				},
			},
		},
		{
			Layer:   "layer8",
			Removed: []string{"usr/local/share/.cache/yarn"},
		},
	}

	return db
}
