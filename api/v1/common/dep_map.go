package common

import (
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
)

type libDepNode struct {
	// Features used by this library.
	features set.StringSet
	// Libraries used by this library directly.
	libraries set.StringSet
	completed bool
}

type circle struct {
	head    string
	members set.StringSet
}

// GetDepMap creates a dependency map from a library to the features it uses.
func GetDepMap(features []database.FeatureVersion) map[string]set.StringSet {
	// Map from a library to its dependency data
	libNodes := make(map[string]*libDepNode)
	// Build the map
	for _, feature := range features {
		fvKey := FeatureNameVersionToString(&v1.FeatureNameVersion{
			Name:    feature.Feature.Name,
			Version: feature.Version,
		})
		// Populate libraries with all direct import.
		for lib, deps := range feature.LibraryToDependencies {
			if node, ok := libNodes[lib]; ok {
				node.libraries = node.libraries.Union(deps)
				node.features.Add(fvKey)
			} else {
				node = &libDepNode{libraries: deps, features: set.NewStringSet(fvKey)}
				libNodes[lib] = node
			}
		}
	}
	// Traverse it and get the dependency map
	depMap := make(map[string]set.StringSet)
	for k, v := range libNodes {
		var cycle *circle
		depMap[k], cycle = fillIn(libNodes, k, v, map[string]int{k: 0})
		if cycle != nil {
			// This is a very rare case that we have a loop in dependency map.
			// All members in the loop should map to the same set of features.
			for c := range cycle.members {
				depMap[c] = depMap[k]
			}
		}
	}
	return depMap
}

func fillIn(libToDep map[string]*libDepNode, depname string, dep *libDepNode, path map[string]int) (set.StringSet, *circle) {
	if dep.completed {
		return dep.features, nil
	}
	var circles []circle
	for lib := range dep.libraries {
		execs, ok := libToDep[lib]
		if !ok {
			logrus.Warnf("Unresolved soname %s", lib)
			continue
		}
		if seq, ok := path[lib]; ok {
			// This is a very rare case that we detect a loop in dependency map.
			// We create a circle and put it in the circles.
			// We use a map from library to its sequence number im path to prioritize the most frequently used code path.
			c := circle{head: lib, members: set.NewStringSet(lib)}
			for p, s := range path {
				if s > seq {
					c.members.Add(p)
				}
			}
			circles = append(circles, c)
			continue
		}
		path[lib] = len(path)
		features, c := fillIn(libToDep, lib, execs, path)
		delete(path, lib)
		if c != nil {
			circles = append(circles, *c)
		}
		dep.features = dep.features.Union(features)
	}
	dep.completed = true
	if len(circles) == 0 {
		return dep.features, nil
	}

	// Again, this is a rare case.
	mc := circle{head: depname, members: set.NewStringSet()}
	for _, c := range circles {
		// This is an extremely rare case we have more than one circles.
		// Merge multiple circles together.
		if path[c.head] < path[mc.head] {
			mc.head = c.head
		}
		mc.members = mc.members.Union(c.members)
	}
	// If this is the head of the circle, resolve the circle by assigning the features
	// of the head to all members
	if mc.head == depname {
		for c := range mc.members {
			libToDep[c].features = dep.features
		}
		return dep.features, nil
	}
	return dep.features, &mc
}
