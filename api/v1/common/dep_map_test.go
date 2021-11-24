package common

import (
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEnrichSoMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		// A base library without any dependencies
		"x1": {
			ProvidedLibraries: []string{"x1.so.1"},
			DependencyToLibraries: database.StringToStringsMap{},
			DependencyToExecutables: database.StringToStringsMap{},
		},
		// An upper layer library depends on x
		"z1": {
			ProvidedLibraries: []string{"z1.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet("z1.so.1"),
			},
			DependencyToExecutables: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet("/bin/z1_exec1", "/bin/z1_exec2"),
			},
		},
		// An executable package depends on that depends on both libraries
		"v1": {
			DependencyToLibraries: database.StringToStringsMap{},
			DependencyToExecutables: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet("/bin/v1_exec1", "/bin/v1_exec4"),
				"z1.so.1": set.NewStringSet("/bin/v1_exec2", "/bin/v1_exec3"),
			},
		},
		// An executable package that depends on upper layer library z1
		"v2": {
			DependencyToExecutables: database.StringToStringsMap{
				"z1.so.1": set.NewStringSet("/bin/v2_exec1", "/bin/v2_exec2"),
			},
		},
		// An executable package depends on base library x1
		"v3": {
			DependencyToExecutables: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet("/bin/v3_exec1"),
			},
		},
		// A compatible library for the upper layer library that is not executable
		"z1-compatible": {
			ProvidedLibraries: []string{"z1.so.1", "z1.so.1.7"},
			DependencyToLibraries: database.StringToStringsMap{
				"x1.so.1": {"z1.so.1": {}, "z1.so.1.7": {}},
				"y.so.1": {"z1.so.1": {}, "z1.so.1.7": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet("/bin/z1c_exec1"),
				"y.so.1":  set.NewStringSet("/bin/z1c_exec2"),
			},
		},
		// An executable package that depends on the compatible library z1-compatible
		"v4": {
			DependencyToExecutables: database.StringToStringsMap{
				"z1.so.1.7": set.NewStringSet("/bin/v4_exec1"),
			},
		},
		// The library used by the compatible library.
		"y": {
			ProvidedLibraries: []string{"y.so.1"},
			DependencyToLibraries: database.StringToStringsMap{},
		},
		// Some executable package with an unresolved dependency, it is not a perfect world
		"v5": {
			DependencyToExecutables: database.StringToStringsMap{
				"unresolved.so.9": {"/bin/v5_exec1": {}},
				"y.so.1": {"/bin/v5_exec2": {}},
			},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)

	assert.Equal(t, featureMap["v4"].DependencyToExecutables["z1.so.1.7"],  depMap["z1.so.1.7"])

	assert.Equal(t, depMap["y.so.1"], depMap["z1.so.1.7"].
		Union(depMap["z1.so.1"]).
		Union(featureMap["v5"].DependencyToExecutables["y.so.1"]).
		Union(featureMap["z1-compatible"].DependencyToExecutables["y.so.1"]))

	assert.Equal(t, depMap["x1.so.1"], depMap["z1.so.1.7"].
		Union(depMap["z1.so.1"]).
		Union(featureMap["z1"].DependencyToExecutables["x1.so.1"]).
		Union(featureMap["z1-compatible"].DependencyToExecutables["x1.so.1"]).
		Union(featureMap["v3"].DependencyToExecutables["x1.so.1"]).
		Union(featureMap["v1"].DependencyToExecutables["x1.so.1"]))

	assert.Equal(t, depMap["z1.so.1"], featureMap["v2"].DependencyToExecutables["z1.so.1"].
		Union(featureMap["v1"].DependencyToExecutables["z1.so.1"]))
}

// Test Topology:
//         x -> y -> z
//         ^         |
//         |_________|
func TestLoopDepMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		"x": {
			ProvidedLibraries: []string{"x.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"z.so.1": {"x.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"z.so.1" : {"/bin/x_exec": {}},
			},
		},
		"y": {
			ProvidedLibraries: []string{"y.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"x.so.1": {"y.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"x.so.1" : {"/bin/y_exec": {}},
			},
		},
		"z": {
			ProvidedLibraries: []string{"z.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"y.so.1": {"z.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"y.so.1" : {"/bin/z_exec": {}},
			},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)
	assert.Len(t, depMap, 3)
	assert.Equal(t, depMap["x.so.1"], depMap["y.so.1"], depMap["z.so.1"])
	assert.Len(t, depMap["x.so.1"], 3)
}

// Test Topology:
//                   |------------
//                   v           |
//         x -> y -> z -> z1 -> z2
//         ^         |
//         |_________|
func TestDoubleLoopDepMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		"x": {
			ProvidedLibraries: []string{"x.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"z.so.1": {"x.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"z.so.1" : {"/bin/x_exec": {}},
			},
		},
		"y": {
			ProvidedLibraries: []string{"y.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"x.so.1": {"y.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"x.so.1" : {"/bin/y_exec": {}},
			},
		},
		"z": {
			ProvidedLibraries: []string{"z.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"y.so.1": {"z.so.1": {}},
				"z2.so.1": {"z.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"y.so.1" : {"/bin/z_exec": {}},
			},
		},
		"z1": {
			ProvidedLibraries: []string{"z1.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"z.so.1": {"z1.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"z.so.1" : {"/bin/z1_exec": {}},
			},
		},
		"z2": {
			ProvidedLibraries: []string{"z2.so.1"},
			DependencyToLibraries: database.StringToStringsMap{
				"z1.so.1": {"z2.so.1": {}},
			},
			DependencyToExecutables: database.StringToStringsMap{
				"z1.so.1" : {"/bin/z2_exec": {}},
			},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)
	assert.Len(t, depMap, 5)
	assert.Equal(t, depMap["x.so.1"], depMap["y.so.1"], depMap["z.so.1"], depMap["z1.so.1"], depMap["z2.so.1"])
	assert.Len(t, depMap["x.so.1"], 5)
}
