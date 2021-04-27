package v1

import (
	"testing"

	archop "github.com/quay/claircore"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
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
				},
			},
		},
	}
	db.vulns[0] = []*database.RHELv2Vulnerability{
		{
			Name: "v1",
			PackageInfos: []*database.RHELv2PackageInfo{
				{
					FixedInVersion: "4",
					Packages: []*database.RHELv2Package{
						{
							Name: "pkg",
							Arch: "x86_64",
						},
					},
					ArchOperation: archop.OpEquals,
				},
			},
		},
		{
			Name: "v2",
			PackageInfos: []*database.RHELv2PackageInfo{
				{
					FixedInVersion: "5",
					Packages: []*database.RHELv2Package{
						{
							Name: "pkg",
							Arch: "i686|ppc64|s390x|x86_64",
						},
					},
					ArchOperation: archop.OpPatternMatch,
				},
			},
		},
		{
			Name: "v3",
			PackageInfos: []*database.RHELv2PackageInfo{
				{
					FixedInVersion: "6",
					Packages: []*database.RHELv2Package{
						{
							Name: "pkg",
							Arch: "x86_64",
						},
					},
					ArchOperation: archop.OpNotEquals,
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
	layer, _, err := LayerFromDatabaseModel(db, dbLayer, true, true)
	assert.NoError(t, err)
	assert.Equal(t, "layer2", layer.Name)
	assert.Equal(t, "", layer.ParentName)
	assert.Equal(t, "rhel:8", layer.NamespaceName)
	features := []Feature{
		{
			Name:          "pkg",
			NamespaceName: "rhel:8",
			VersionFormat: rpm.ParserName,
			Version:       "2",
			AddedBy:       "layer1",
			Location:      "var/lib/rpm/Packages",
			FixedBy:       "5",
			Vulnerabilities: []Vulnerability{
				{
					Name:          "v1",
					NamespaceName: "rhel:8",
					FixedBy:       "4",
					Metadata: map[string]interface{}{
						"Red Hat": &types.Metadata{
							PublishedDateTime:    "0001-01-01 00:00:00 +0000 UTC",
							LastModifiedDateTime: "0001-01-01 00:00:00 +0000 UTC",
						},
					},
				},
				{
					Name:          "v2",
					NamespaceName: "rhel:8",
					FixedBy:       "5",
					Metadata: map[string]interface{}{
						"Red Hat": &types.Metadata{
							PublishedDateTime:    "0001-01-01 00:00:00 +0000 UTC",
							LastModifiedDateTime: "0001-01-01 00:00:00 +0000 UTC",
						},
					},
				},
			},
		},
	}
	assert.ElementsMatch(t, layer.Features, features)
}
