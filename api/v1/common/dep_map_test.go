package common

import (
	"fmt"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEnrichSoMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		// A base library without any dependencies
		"x1": {
			ProvidedLibraries: map[string][]string{
				"x1.so.1": {},
			},
			NeededLibrariesMap: map[string][]string{},
		},
		// An upper layer library depends on x
		"z1": {
			ProvidedLibraries: map[string][]string{
				"z1.so.1": {"x1.so.1"},
			},
			NeededLibrariesMap: map[string][]string{
				"x1.so.1": {"/bin/z1_exec1", "/bin/z1_exec2"},
			},
		},
		// An executable package depends on that depends on both libraries
		"v1": {
			ProvidedLibraries: map[string][]string{},
			NeededLibrariesMap: map[string][]string{
				"x1.so.1": {"/bin/v1_exec1", "/bin/v1_exec4"},
				"z1.so.1": {"/bin/v1_exec2", "/bin/v1_exec3"},
			},
		},
		// An executable package that depends on upper layer library z1
		"v2": {
			NeededLibrariesMap: map[string][]string{
				"z1.so.1": {"/bin/v2_exec1", "/bin/v2_exec2"},
			},
		},
		// An executable package depends on base library x1
		"v3": {
			NeededLibrariesMap: map[string][]string{
				"x1.so.1": {"/bin/v3_exec1"},
			},
		},
		// A compatible library for the upper layer library that is not executable
		"z1-compatible": {
			ProvidedLibraries: map[string][]string{
				"z1.so.1": {"x1.so.1", "y.so.1"},
				"z1.so.1.7": {"x1.so.1", "y.so.1"},
			},
			NeededLibrariesMap: map[string][]string{
				"x1.so.1": {"/bin/z1c_exec1"},
				"y.so.1": {"/bin/z1c_exec2"},
			},
		},
		// An executable package that depends on the compatible library z1-compatible
		"v4": {
			NeededLibrariesMap: map[string][]string{
				"z1.so.1.7": {"/bin/v4_exec1"},
			},
		},
		// The library used by the compatible library.
		"y": {
			ProvidedLibraries: map[string][]string{
				"y.so.1": {},
			},
		},
		// Some executable package with an unresolved dependency, it is not a perfect world
		"v5": {
			NeededLibrariesMap: map[string][]string{
				"unresolved.so.9": {"/bin/v5_exec1"},
				"y.so.1": {"/bin/v5_exec2"},
			},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)
	for k, v := range depMap {
		fmt.Println(k, v)
	}

	assert.Equal(t, featureMap["v4"].NeededLibrariesMap["z1.so.1.7"],  depMap["z1.so.1.7"].AsSlice())
	// assert.NotContains(t, depMap, "unresolved.so.9")

	verifyAndRemove(t, depMap["y.so.1"], depMap["z1.so.1.7"].AsSlice()...)
	verifyAndRemove(t, depMap["y.so.1"], depMap["z1.so.1"].AsSlice()...)
	verifyAndRemove(t, depMap["y.so.1"], featureMap["v5"].NeededLibrariesMap["y.so.1"]...)
	verifyAndRemove(t, depMap["y.so.1"], featureMap["z1-compatible"].NeededLibrariesMap["y.so.1"]...)
	assert.Empty(t, depMap["y.so.1"])

	verifyAndRemove(t, depMap["x1.so.1"], depMap["z1.so.1.7"].AsSlice()...)
	verifyAndRemove(t, depMap["x1.so.1"], depMap["z1.so.1"].AsSlice()...)
	verifyAndRemove(t, depMap["x1.so.1"], featureMap["z1"].NeededLibrariesMap["x1.so.1"]...)
	verifyAndRemove(t, depMap["x1.so.1"], featureMap["z1-compatible"].NeededLibrariesMap["x1.so.1"]...)
	verifyAndRemove(t, depMap["x1.so.1"], featureMap["v3"].NeededLibrariesMap["x1.so.1"]...)
	verifyAndRemove(t, depMap["x1.so.1"], featureMap["v1"].NeededLibrariesMap["x1.so.1"]...)
	assert.Empty(t, depMap["x1.so.1"])

	verifyAndRemove(t, depMap["z1.so.1"], featureMap["v2"].NeededLibrariesMap["z1.so.1"]...)
	verifyAndRemove(t, depMap["z1.so.1"], featureMap["v1"].NeededLibrariesMap["z1.so.1"]...)
	assert.Empty(t, depMap["z1.so.1"])


}

func verifyAndRemove(t *testing.T, d set.StringSet, items ...string) {
	for _, item := range items {
		assert.True(t, d.Remove(item))
	}
}
