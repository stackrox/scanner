package v1

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Register the CPE validators.
	_ "github.com/stackrox/scanner/cpe/validation/all"
	// Register the version format parsers.
	_ "github.com/stackrox/scanner/ext/versionfmt/dpkg"
	_ "github.com/stackrox/scanner/ext/versionfmt/language"
	_ "github.com/stackrox/scanner/ext/versionfmt/rpm"
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

func TestLatestUbuntuFeatureVersion(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	dbLayer := database.Layer{
		Name:          "example",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "ubuntu:14.04",
			VersionFormat: "dpkg",
		},
		Features: []database.FeatureVersion{
			{
				Version: "7.35.0-1ubuntu2.20",
				Feature: database.Feature{
					Name: "curl",
					Namespace: database.Namespace{
						Name:          "ubuntu:14.04",
						VersionFormat: "dpkg",
					},
				},
				AddedBy: database.Layer{
					Name: "example",
				},
				AffectedBy: []database.Vulnerability{
					{
						Name:    "CVE-2019-5482",
						FixedBy: "7.35.0-1ubuntu2.20+esm3",
					},
					{
						Name:    "CVE-2019-5436",
						FixedBy: "7.35.0-1ubuntu2.20+esm2",
					},
				},
			},
		},
	}
	layer, _, err := LayerFromDatabaseModel(nil, dbLayer, &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "7.35.0-1ubuntu2.20+esm3", layer.Features[0].FixedBy)
}

func TestLatestCentOSFeatureVersion(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	dbLayer := database.Layer{
		Name:          "example",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "centos:8",
			VersionFormat: "rpm",
		},
		Features: []database.FeatureVersion{
			{
				Version: "3.26.0-6.el8",
				Feature: database.Feature{
					Name: "sqlite-libs",
					Namespace: database.Namespace{
						Name:          "centos:8",
						VersionFormat: "rpm",
					},
				},
				AddedBy: database.Layer{
					Name: "example",
				},
				AffectedBy: []database.Vulnerability{
					{
						Name:    "CVE-2020-15358",
						FixedBy: "",
					},
					{
						Name:    "CVE-2020-13632",
						FixedBy: "0:3.26.0-11.el8",
					},
					{
						Name:    "CVE-2021-1234",
						FixedBy: "",
					},
					{
						Name:    "CVE-2021-1235",
						FixedBy: "0:3.27.1-12.el8",
					},
					{
						Name:    "CVE-2020-13630",
						FixedBy: "0:3.26.0-11.el8",
					},
				},
			},
		},
	}
	layer, _, err := LayerFromDatabaseModel(nil, dbLayer, &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "0:3.27.1-12.el8", layer.Features[0].FixedBy)
}

func TestLatestLanguageFeatureVersion(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()

	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("NVD_DEFINITIONS_DIR", defsDir)

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

	addLanguageVulns(db, dbLayer, false)
	assert.Equal(t, "2.3.29", dbLayer.Features[0].FixedBy)
}

func TestNotesNoLanguageVulns(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, nil)
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, nil)
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, nil)
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	assert.Contains(t, notes, OSCVEsUnavailable)
}

type mockDatastore struct {
	database.MockDatastore
	layers map[string][]*component.LayerToComponents
}

func newMockDatastore() *mockDatastore {
	db := &mockDatastore{
		layers: make(map[string][]*component.LayerToComponents),
	}
	db.FctGetLayerLanguageComponents = func(layer string, opts *database.DatastoreOptions) ([]*component.LayerToComponents, error) {
		return db.layers[layer], nil
	}
	return db
}

func TestAddLanguageVulns(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()

	_, filename, _, _ := runtime.Caller(0)
	defsDir := filepath.Join(filepath.Dir(filename), "/testdata")
	envIsolator.Setenv("NVD_DEFINITIONS_DIR", defsDir)

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

	layer := &Layer{
		Name: "layer2",
	}
	addLanguageVulns(db, layer, false)
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
	addLanguageVulns(db, layer, false)
	assert.Len(t, layer.Features, 2)

	layer = &Layer{
		Name: "layer4",
	}
	addLanguageVulns(db, layer, false)
	assert.Empty(t, layer.Features)

	layer = &Layer{
		Name: "layer6",
	}
	addLanguageVulns(db, layer, false)
	assert.Len(t, layer.Features, 1)
	feature = layer.Features[0]
	assert.Equal(t, "microsoft.dotnetcore.app", feature.Name)
	assert.Equal(t, "3.2.0", feature.Version)
	assert.Equal(t, "usr/share/dotnet/shared/Microsoft.NETCore.App/3.2.0/", feature.Location)
	assert.Equal(t, "layer5", feature.AddedBy)

	layer = &Layer{
		Name: "layer8",
	}
	addLanguageVulns(db, layer, false)
	assert.Empty(t, layer.Features)
}
