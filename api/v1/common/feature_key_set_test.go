package common

import (
	"testing"

	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stretchr/testify/assert"
)

func TestFeatureKeySet(t *testing.T) {
	var a, b FeatureKeySet
	a.Merge(b)
	assert.Nil(t, a)

	f0 := featurefmt.PackageKey{Name: "a", Version: "v1"}
	f1 := featurefmt.PackageKey{Name: "b", Version: "v2"}
	f2 := featurefmt.PackageKey{Name: "c", Version: "v3"}

	a = FeatureKeySet{featurefmt.PackageKey{Name: "a", Version: "v1"}: {}}
	b.Merge(a)
	assert.Equal(t, a, b)
	a.Add(f1)
	b.Add(f2)
	a.Merge(b)
	assert.Len(t, a, 3)
	assert.Contains(t, a, f1, f2, f0)
}
