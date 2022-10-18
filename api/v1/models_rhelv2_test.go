package v1

import (
	"sort"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/archop"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/testutils"
	"github.com/stackrox/scanner/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockRHELv2Datastore struct {
	database.MockDatastore

	layers map[string][]*database.RHELv2Layer

	vulns map[int][]*database.RHELv2Vulnerability
}

func newMockRHELv2Datastore() *mockRHELv2Datastore {
	db := &mockRHELv2Datastore{
		layers: make(map[string][]*database.RHELv2Layer),
		vulns:  make(map[int][]*database.RHELv2Vulnerability),
	}
	db.FctGetRHELv2Layers = func(layer string) ([]*database.RHELv2Layer, error) {
		return db.layers[layer], nil
	}
	db.FctGetRHELv2Vulnerabilities = func(records []*database.RHELv2Record) (map[int][]*database.RHELv2Vulnerability, error) {
		vulns := make(map[int][]*database.RHELv2Vulnerability)
		uniqueVulns := make(map[int]set.StringSet)
		for _, r := range records {
			id := r.Pkg.ID
			if _, ok := uniqueVulns[id]; !ok {
				uniqueVulns[id] = set.NewStringSet()
			}
			uniqueSet := uniqueVulns[id]
			for _, vuln := range db.vulns[id] {
				if uniqueSet.Add(vuln.Name) {
					vulns[id] = append(vulns[id], vuln)
				}
			}
		}
		return vulns, nil
	}
	return db
}

func TestLayerFromDatabaseModelRHELv2(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")

	now := time.Now()
	db := newMockRHELv2Datastore()
	// 3 layer image with deleted package.
	db.layers["layer2"] = []*database.RHELv2Layer{
		{
			Hash: "layer0",
			Dist: "rhel8",
		},
		{
			Hash:       "layer1",
			ParentHash: "layer0",
			Dist:       "rhel:8",
			Pkgs: []*database.RHELv2Package{
				{
					Name:    "pkg",
					Version: "2",
					Arch:    "x86_64",
					ExecutableToDependencies: database.StringToStringsMap{
						"/exec/me":     {},
						"/pls/exec/me": {},
					},
				},
				{
					Name:    "pkg2",
					Version: "3",
					Arch:    "x86_64",
				},
			},
			CPEs: []string{"cpe", "cpe1"},
		},
		{
			Hash:       "layer2",
			ParentHash: "layer1",
			Dist:       "rhel:8",
			Pkgs: []*database.RHELv2Package{
				{
					Name:    "pkg",
					Version: "2",
					Arch:    "x86_64",
					ExecutableToDependencies: database.StringToStringsMap{
						"/exec/me":     {},
						"/pls/exec/me": {},
					},
				},
			},
		},
	}
	db.vulns[0] = []*database.RHELv2Vulnerability{
		{
			Name: "v1",
			Packages: []*database.RHELv2Package{
				{
					Name: "pkg",
					Arch: "x86_64",

					FixedInVersion: "4",
					ArchOperation:  archop.OpEquals,
				},
			},
			Issued: now,
		},
		{
			Name: "v2",
			Packages: []*database.RHELv2Package{
				{
					Name: "pkg",
					Arch: "i686|ppc64|s390x|x86_64",

					FixedInVersion: "5",
					ArchOperation:  archop.OpPatternMatch,
				},
			},
			Issued:  now,
			Updated: now,
		},
		{
			Name: "v3",
			Packages: []*database.RHELv2Package{
				{
					Name: "pkg",
					Arch: "x86_64",

					FixedInVersion: "6",
					ArchOperation:  archop.OpNotEquals,
				},
			},
		},
	}

	dbLayer := database.Layer{
		Name:          "layer2",
		EngineVersion: 0,
		Parent:        nil,
		Namespace: &database.Namespace{
			Name:          "rhel:8",
			VersionFormat: "rpm",
		},
		Features: nil,
	}
	layer, _, err := LayerFromDatabaseModel(db, dbLayer, "", nil, &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "layer2", layer.Name)
	assert.Equal(t, "", layer.ParentName)
	assert.Equal(t, "rhel:8", layer.NamespaceName)
	features := []Feature{
		{
			Name:          "pkg",
			NamespaceName: "rhel:8",
			VersionFormat: rpm.ParserName,
			Version:       "2.x86_64",
			AddedBy:       "layer1",
			FixedBy:       "5",
			Executables: []*v1.Executable{
				{
					Path: "/exec/me",
					RequiredFeatures: []*v1.FeatureNameVersion{
						{Name: "pkg", Version: "2.x86_64"},
					},
				},
				{
					Path: "/pls/exec/me",
					RequiredFeatures: []*v1.FeatureNameVersion{
						{Name: "pkg", Version: "2.x86_64"},
					},
				},
			},
			Vulnerabilities: []Vulnerability{
				{
					Name:          "v1",
					NamespaceName: "rhel:8",
					FixedBy:       "4",
					Metadata: map[string]interface{}{
						"Red Hat": &types.Metadata{
							PublishedDateTime: now.Format(timeFormat),
						},
					},
				},
				{
					Name:          "v2",
					NamespaceName: "rhel:8",
					FixedBy:       "5",
					Metadata: map[string]interface{}{
						"Red Hat": &types.Metadata{
							PublishedDateTime:    now.Format(timeFormat),
							LastModifiedDateTime: now.Format(timeFormat),
						},
					},
				},
			},
		},
	}
	for _, feature := range layer.Features {
		sort.Slice(feature.Executables, func(i, j int) bool {
			return feature.Executables[i].Path < feature.Executables[j].Path
		})
	}
	assert.ElementsMatch(t, layer.Features, features)
}

func TestComponentsFromDatabaseModelRHELv2(t *testing.T) {
	envIsolator := testutils.NewEnvIsolator(t)
	defer envIsolator.RestoreAll()
	envIsolator.Setenv(env.LanguageVulns.EnvVar(), "false")

	db := newMockRHELv2Datastore()
	db.layers["layer1"] = []*database.RHELv2Layer{
		{
			Hash: "layer1",
			Dist: "rhel:7",
			Pkgs: []*database.RHELv2Package{
				{
					Model:                    database.Model{ID: 3},
					Name:                     "pkg",
					Version:                  "22",
					Arch:                     "x86_64",
					Module:                   "idk",
					ExecutableToDependencies: database.StringToStringsMap{"executable": {}},
				},
			},
			CPEs: []string{"my-cpe"},
		},
	}
	// Vulns for the testing pkg.
	db.vulns[0] = []*database.RHELv2Vulnerability{
		{
			Name: "vuln",
		},
	}

	layer := &database.Layer{
		Name: "layer1",
		Namespace: &database.Namespace{
			Name:          "rhel:7",
			VersionFormat: "rpm",
		},
	}
	imgComponents, err := ComponentsFromDatabaseModel(db, layer, "", false)
	assert.NoError(t, err)

	expectedRHELv2PkgEnvs := map[int]*database.RHELv2PackageEnv{
		3: {
			Pkg: &database.RHELv2Package{
				Model:                    database.Model{ID: 3},
				Name:                     "pkg",
				Version:                  "22",
				Module:                   "idk",
				Arch:                     "x86_64",
				ExecutableToDependencies: database.StringToStringsMap{"executable": {}},
			},
			Namespace: "rhel:7",
			AddedBy:   "layer1",
			CPEs:      []string{"my-cpe"},
		},
	}
	expectedNotes := []Note{LanguageCVEsUnavailable}

	assert.Empty(t, imgComponents.Features)

	assert.Empty(t, imgComponents.LanguageComponents)
	assert.Equal(t, expectedRHELv2PkgEnvs, imgComponents.RHELv2PkgEnvs)
	assert.ElementsMatch(t, expectedNotes, imgComponents.Notes)
}
