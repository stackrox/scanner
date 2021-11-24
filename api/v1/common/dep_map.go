package common

import (
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
)

type usedByNode struct {
	// Executables that uses this library.
	executables  set.StringSet
	// Libraries that imported this library directly.
	libraries    set.StringSet
	completed    bool
}

type circle struct {
	head string
	all set.StringSet
}

func GetDepMap(features []database.FeatureVersion) map[string]set.StringSet {
	// Map from a library to its dependency data
	depToUsedByNode := make(map[string]*usedByNode)

	// Build the map
	for _, feature := range features {
		// Populate libraries with all direct import.
		for dep, libs := range feature.DependencyToLibraries {
			if node, ok := depToUsedByNode[dep]; ok {
				node.libraries = node.libraries.Union(libs)
			} else {
				node = &usedByNode{libraries: libs}
				depToUsedByNode[dep] = node
			}
		}
		// Populate executables with all direct use.
		for dep, execs := range feature.DependencyToExecutables {
			if node, ok := depToUsedByNode[dep]; ok {
				node.executables = node.executables.Union(execs)
			} else {
				node = &usedByNode{executables: execs}
				depToUsedByNode[dep] = node
			}
		}
	}
	// Traverse it and get the dependency map
	depMap := make(map[string]set.StringSet)
	for k, v := range depToUsedByNode {
		var cycle *circle
		depMap[k], cycle = fillIn(depToUsedByNode, k, v, map[string]int{k: 0})
		if cycle != nil {
			// This is a very rare case that we have a loop in dependency map.
			// All members in the loop should map to the same set of executables.
			for c := range cycle.all {
				depMap[c] = depMap[k]
			}
		}
	}
	return depMap
}

func fillIn(libToDep map[string]*usedByNode, depname string, dep *usedByNode, path map[string]int) (set.StringSet, *circle) {
	if dep.completed {
		return dep.executables, nil
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
			c := circle{head: lib, all: set.NewStringSet(lib)}
			for p, s := range path  {
				if s > seq {
					c.all.Add(p)
				}
			}
			circles = append(circles, c)
			continue
		}
		path[lib] = len(path)
		executables, c := fillIn(libToDep, lib, execs, path)
		delete(path, lib)
		if c != nil {
			circles = append(circles, *c)
		}
		dep.executables = dep.executables.Union(executables)
	}
	dep.completed = true
	if len(circles) == 0 {
		return dep.executables, nil
	}

	// Again, this is a rare case.
	mc := circle{head: depname, all: set.NewStringSet()}
	for _, c := range circles {
		// This is an extremely rare case we have more than one circles.
		// Merge multiple circles together.
		if path[c.head] < path[mc.head] {
			mc.head = c.head
		}
		mc.all = mc.all.Union(c.all)
	}
	// If this is the head of the circle, resolve the circle by assigning the executables
	// of the head to all members
	if mc.head == depname {
		for c := range mc.all {
			libToDep[c].executables = dep.executables
		}
		return dep.executables, nil
	}
	return dep.executables, &mc
}

