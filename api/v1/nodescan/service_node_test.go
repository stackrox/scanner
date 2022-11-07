package nodescan

import (
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/cpe/nvdtoolscache"
	"github.com/stackrox/scanner/database"
	k8scache "github.com/stackrox/scanner/k8s/cache"

	"testing"
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

func TestGetNodeVulnerabilities(t *testing.T) {
	t.Skipf("Test under development")
	var nvdVulnCache nvdtoolscache.Cache
	var k8sVulnCache k8scache.Cache
	nvdVulnCache = nvdtoolscache.Singleton()
	k8sVulnCache = k8scache.Singleton()
	db := newMockRHELv2Datastore()
	svc := NewService(db, nvdVulnCache, k8sVulnCache)
	_ = svc // TODO: continue here further
}
