package v1

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Register the CPE validators.
	_ "github.com/stackrox/scanner/cpe/validation/all"
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

func TestNotesNoLanguageVulns(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(features.LanguageVulns.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	dbLayer := database.Layer{
		Name:          "example",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "ubuntu:20.04",
			VersionFormat: "dpkg",
		},
		Features: nil,
	}
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, false, false)
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	assert.Contains(t, notes, LanguageCVEsUnavailable)
}

func TestNotesStaleCVEs(t *testing.T) {
	dbLayer := database.Layer{
		Name:          "example",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "ubuntu:13.04",
			VersionFormat: "dpkg",
		},
		Features: nil,
	}
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, false, false)
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	assert.Contains(t, notes, OSCVEsStale)
}

func TestNotesUnavailableCVEs(t *testing.T) {
	dbLayer := database.Layer{
		Name:          "example",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "fedora:32",
			VersionFormat: "rpm",
		},
		Features: nil,
	}
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, false, false)
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	assert.Contains(t, notes, OSCVEsUnavailable)
}

type mockDatastore struct {
	database.MockDatastore
	layers map[string][]*component.LayerToComponents
}

func newMockDatastore() *mockDatastore {
	return &mockDatastore{
		layers: make(map[string][]*component.LayerToComponents),
	}
}

func TestAddLanguageVulns(t *testing.T) {
	prevVal := os.Getenv("NVD_DEFINITIONS_DIR")
	defer require.NoError(t, os.Setenv("NVD_DEFINITIONS_DIR", prevVal))
	prevBoltPath := nvdtoolscache.BoltPath
	defer func() {
		nvdtoolscache.BoltPath = prevBoltPath
	}()

	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	require.NoError(t, os.Setenv("NVD_DEFINITIONS_DIR", defsDir))

	dir, err := ioutil.TempDir("", "bolt")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	nvdtoolscache.BoltPath = filepath.Join(dir, "temp.db")

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
	db.FctGetLayerLanguageComponents = func(layer string) ([]*component.LayerToComponents, error) {
		return db.layers[layer], nil
	}

	layer := &Layer{
		Name: "layer2",
	}
	addLanguageVulns(db, layer)
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
	addLanguageVulns(db, layer)
	assert.Len(t, layer.Features, 2)

	layer = &Layer{
		Name: "layer4",
	}
	addLanguageVulns(db, layer)
	assert.Empty(t, layer.Features)

	layer = &Layer{
		Name: "layer6",
	}
	addLanguageVulns(db, layer)
	assert.Len(t, layer.Features, 1)
	feature = layer.Features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Equal(t, "layer5", feature.AddedBy)
}
