package common

import (
	"testing"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stretchr/testify/assert"
)

func TestCreateDepMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		// A base library without any dependencies
		"x1": {
			Feature:               database.Feature{Name: "x1"},
			LibraryToDependencies: database.StringToStringsMap{"x1.so.1": set.NewStringSet()},
		},
		// An upper layer library depends on x
		"z1": {
			Feature: database.Feature{Name: "z1"},
			LibraryToDependencies: database.StringToStringsMap{
				"z1.so.1": set.NewStringSet("x1.so.1"),
			},
		},
		// A compatible library for the upper layer library that is not executable
		"z1-compatible": {
			Feature: database.Feature{Name: "z1c"},
			LibraryToDependencies: database.StringToStringsMap{
				"z1.so.1":   set.NewStringSet("x1.so.1", "y.so.1"),
				"z1.so.1.7": set.NewStringSet("x1.so.1", "y.so.1"),
			},
		},
		// The library used by the compatible library.
		"y": {
			Feature:               database.Feature{Name: "y"},
			LibraryToDependencies: database.StringToStringsMap{"y.so.1": set.NewStringSet()},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)

	assert.Equal(t, FeatureKeySet{featurefmt.PackageKey{Name: featureMap["x1"].Feature.Name}: {}}, depMap["x1.so.1"])
	assert.Equal(t, FeatureKeySet{featurefmt.PackageKey{Name: featureMap["y"].Feature.Name}: {}}, depMap["y.so.1"])
	assert.Len(t, depMap["z1.so.1"], 4)
	assert.Contains(t, depMap["z1.so.1.7"],
		featurefmt.PackageKey{Name: featureMap["x1"].Feature.Name},
		featurefmt.PackageKey{Name: featureMap["y"].Feature.Name},
		featurefmt.PackageKey{Name: featureMap["z1"].Feature.Name},
	)
}

// Test Topology:  x -> y means x is used by y.
//
//	x -> y -> z
//	^         |
//	|_________|
func TestLoopDepMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		"x": {
			Feature: database.Feature{Name: "x"},
			LibraryToDependencies: database.StringToStringsMap{
				"x.so.1": set.NewStringSet("z.so.1"),
			},
		},
		"y": {
			Feature: database.Feature{Name: "y"},
			LibraryToDependencies: database.StringToStringsMap{
				"y.so.1": set.NewStringSet("x.so.1"),
			},
		},
		"z": {
			Feature: database.Feature{Name: "z"},
			LibraryToDependencies: database.StringToStringsMap{
				"z.so.1": set.NewStringSet("y.so.1"),
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

// Test Topology: x -> y means x is used by y.
//
//	                |------------
//	                v           |
//	x1 -> x -> y -> z -> z1 -> z2 -> z3
//	      ^         |
//	      |_________|
func TestDoubleLoopDepMap(t *testing.T) {
	featureMap := map[string]database.FeatureVersion{
		"x1": {
			Feature: database.Feature{Name: "x1"},
			LibraryToDependencies: database.StringToStringsMap{
				"x1.so.1": set.NewStringSet(),
			},
		},
		"x": {
			Feature: database.Feature{Name: "x"},
			LibraryToDependencies: database.StringToStringsMap{
				"x.so.1": set.NewStringSet("z.so.1", "x1.so.1"),
			},
		},
		"y": {
			Feature: database.Feature{Name: "y"},
			LibraryToDependencies: database.StringToStringsMap{
				"y.so.1": set.NewStringSet("x.so.1"),
			},
		},
		"z": {
			Feature: database.Feature{Name: "z"},
			LibraryToDependencies: database.StringToStringsMap{
				"z.so.1": set.NewStringSet("y.so.1", "z2.so.1"),
			},
		},
		"z1": {
			Feature: database.Feature{Name: "z1"},
			LibraryToDependencies: database.StringToStringsMap{
				"z1.so.1": set.NewStringSet("z.so.1"),
			},
		},
		"z2": {
			Feature: database.Feature{Name: "z2"},
			LibraryToDependencies: database.StringToStringsMap{
				"z2.so.1": set.NewStringSet("z1.so.1"),
			},
		},
		"z3": {
			Feature: database.Feature{Name: "z3"},
			LibraryToDependencies: database.StringToStringsMap{
				"z3.so.1": set.NewStringSet("z2.so.1"),
			},
		},
	}
	var features []database.FeatureVersion
	for _, feature := range featureMap {
		features = append(features, feature)
	}
	depMap := GetDepMap(features)
	assert.Len(t, depMap, 7)
	assert.Equal(t, depMap["y.so.1"], depMap["z.so.1"], depMap["z1.so.1"], depMap["z2.so.1"])
	assert.Len(t, depMap["x.so.1"], 6)
	assert.Len(t, depMap["x1.so.1"], 1)
	allFeatures := make(FeatureKeySet)
	for _, feature := range featureMap {
		allFeatures.Add(featurefmt.PackageKey{Name: feature.Feature.Name})
	}
	assert.Len(t, depMap["z3.so.1"], 7)
	assert.Equal(t, allFeatures, depMap["z3.so.1"])
}
