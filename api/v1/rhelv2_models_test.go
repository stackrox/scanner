package v1

import (
	"testing"
	"time"

	archop "github.com/quay/claircore"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/env"
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
	t.Setenv(env.LanguageVulns.EnvVar(), "false")

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
					Name:                "pkg",
					Version:             "2",
					Arch:                "x86_64",
					ProvidedExecutables: []string{"/exec/me", "/pls/exec/me"},
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
					Name:                "pkg",
					Version:             "2",
					Arch:                "x86_64",
					ProvidedExecutables: []string{"/exec/me", "/pls/exec/me"},
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
			Issued: now,
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
			Issued:  now,
			Updated: now,
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
	layer, _, err := LayerFromDatabaseModel(db, dbLayer, "", &database.DatastoreOptions{
		WithVulnerabilities: true,
		WithFeatures:        true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "layer2", layer.Name)
	assert.Equal(t, "", layer.ParentName)
	assert.Equal(t, "rhel:8", layer.NamespaceName)
	features := []Feature{
		{
			Name:                "pkg",
			NamespaceName:       "rhel:8",
			VersionFormat:       rpm.ParserName,
			Version:             "2.x86_64",
			AddedBy:             "layer1",
			FixedBy:             "5",
			ProvidedExecutables: []string{"/exec/me", "/pls/exec/me"},
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
	assert.ElementsMatch(t, layer.Features, features)
}
