package v1

import (
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stretchr/testify/assert"
	// Register the CPE validators.
	_ "github.com/stackrox/scanner/cpe/validation/all"
	// Register the version format parsers.
	_ "github.com/stackrox/scanner/ext/versionfmt/dpkg"
	_ "github.com/stackrox/scanner/ext/versionfmt/language"
	_ "github.com/stackrox/scanner/ext/versionfmt/rpm"
)

func TestLatestUbuntuFeatureVersion(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	providedExecs := []string{"/exec/me", "/pls/exec/me"}

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
				ProvidedExecutables: providedExecs,
			},
		},
	}
	layer, _, err := LayerFromDatabaseModel(nil, dbLayer, "", &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "7.35.0-1ubuntu2.20+esm3", layer.Features[0].FixedBy)
	assert.ElementsMatch(t, providedExecs, layer.Features[0].ProvidedExecutables)
}

func TestLatestCentOSFeatureVersion(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")
	defer envIsolator.RestoreAll()

	providedExecs := []string{"/exec/me", "/pls/exec/me"}

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
				ProvidedExecutables: providedExecs,
			},
		},
	}
	layer, _, err := LayerFromDatabaseModel(nil, dbLayer, "", &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "0:3.27.1-12.el8", layer.Features[0].FixedBy)
	assert.ElementsMatch(t, providedExecs, layer.Features[0].ProvidedExecutables)
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, "", nil)
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, "", nil)
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
	_, notes, err := LayerFromDatabaseModel(nil, dbLayer, "", nil)
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
	db.FctGetLayerLanguageComponents = func(layer, lineage string, opts *database.DatastoreOptions) ([]*component.LayerToComponents, error) {
		return db.layers[layer], nil
	}
	return db
}

func TestComponentsFromDatabaseModel(t *testing.T) {
	db := newMockDatastore()

	dbLayer := database.Layer{
		Name: "layer1",
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
					Name: "layer1",
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

	db.layers["layer1"] = []*component.LayerToComponents{
		{
			Layer: "layer0",
			Components: []*component.Component{
				{
					Name:       "javapkg",
					Version:    "1.2.3",
					SourceType: component.JavaSourceType,
					Location:   "/opt/java/pkg/location",
					JavaPkgMetadata: &component.JavaPkgMetadata{
						ImplementationVersion: "1",
						MavenVersion:          "2",
						Origins:               []string{"idk"},
						SpecificationVersion:  "something",
						BundleName:            "bundle",
					},
				},
				{
					Name:               "ospkg",
					Version:            "1.2.3",
					FromPackageManager: true,
					SourceType:         component.DotNetCoreRuntimeSourceType,
				},
				{
					Name:       "pythonpkg",
					Version:    "2.2.3",
					SourceType: component.PythonSourceType,
					Location:   "/opt/python/pkg/location",
					PythonPkgMetadata: &component.PythonPkgMetadata{
						Homepage:    "pkg.com",
						AuthorEmail: "stackrox",
						DownloadURL: "pkg.com/stackrox",
						Summary:     "this is the coolest package ever",
						Description: "something something something",
					},
				},
				{
					Name:       "removedpkg",
					Version:    "1.2.3",
					SourceType: component.GemSourceType,
					Location:   "/something/removed",
				},
			},
		},
		{
			Layer:   "layer1",
			Removed: []string{"/something/removed"},
		},
	}

	imgComponents, err := ComponentsFromDatabaseModel(db, &dbLayer, "", true)
	assert.NoError(t, err)

	expectedFeatures := []Feature{
		{
			Name:          "sqlite-libs",
			NamespaceName: "centos:8",
			VersionFormat: "rpm",
			Version:       "3.26.0-6.el8",
			AddedBy:       "layer1",
		},
	}
	expectedComponents := []*component.Component{
		{
			Name:       "javapkg",
			Version:    "1.2.3",
			SourceType: component.JavaSourceType,
			Location:   "/opt/java/pkg/location",
			JavaPkgMetadata: &component.JavaPkgMetadata{
				ImplementationVersion: "1",
				MavenVersion:          "2",
				Origins:               []string{"idk"},
				SpecificationVersion:  "something",
				BundleName:            "bundle",
			},
			AddedBy: "layer0",
		},
		{
			Name:       "pythonpkg",
			Version:    "2.2.3",
			SourceType: component.PythonSourceType,
			Location:   "/opt/python/pkg/location",
			PythonPkgMetadata: &component.PythonPkgMetadata{
				Homepage:    "pkg.com",
				AuthorEmail: "stackrox",
				DownloadURL: "pkg.com/stackrox",
				Summary:     "this is the coolest package ever",
				Description: "something something something",
			},
			AddedBy: "layer0",
		},
	}
	expectedNotes := []Note{CertifiedRHELScanUnavailable}

	assert.ElementsMatch(t, expectedFeatures, imgComponents.Features)
	assert.Empty(t, imgComponents.RHELv2PkgEnvs)
	assert.ElementsMatch(t, expectedComponents, imgComponents.LanguageComponents)
	assert.ElementsMatch(t, expectedNotes, imgComponents.Notes)
}
