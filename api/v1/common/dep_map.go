package common

import (
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
)

type libDep struct {
	// Executables that uses this library
	executables  set.StringSet
	// Libraries that uses this library
	libraries    set.StringSet
	completed    bool
}

func GetDepMap(features []database.FeatureVersion) map[string]set.StringSet {
	// Map from libname to its dependency data
	libToDep := make(map[string]*libDep)

	// Build the map
	for _, feature := range features {
		for lib, dependencies := range feature.LibraryToDependencies {
			for dep := range dependencies {
				data, ok := libToDep[dep]
				if !ok {
					data = &libDep{}
				}
				data.libraries.Add(lib)
				libToDep[dep] = data
			}
		}
		// Add executables
		for lib, execs := range feature.DependencyToExecutables {
			if dep, ok := libToDep[lib]; ok {
				dep.executables = dep.executables.Union(execs)
			} else {
				dep= &libDep{executables: execs}
				libToDep[lib] = dep
			}
		}
	}
	// Traverse it and get the results
	depMap := make(map[string]set.StringSet)
	for k, v := range libToDep {
		var cycle *circle
		depMap[k], cycle = fillIn(libToDep, k, v, map[string]int{k: 0})
		if cycle != nil {
			for c := range cycle.all {
				depMap[c] = depMap[k]
			}
		}
	}
	return depMap
}

func fillIn(libToDep map[string]*libDep, depname string, dep *libDep, path map[string]int) (set.StringSet, *circle) {
	if dep.completed {
		return dep.executables, nil
	}
	var cycles []circle
	for soname := range dep.libraries {
		if value, ok := libToDep[soname]; !ok {
			logrus.Warnf("Unresolved soname %s", soname)
		} else {
			// Very rare case
			if seq, ok := path[soname]; ok {
				c := circle{head: soname, all: set.NewStringSet(soname)}
				for lib, s := range path  {
					if s > seq {
						c.all.Add(lib)
					}
				}
				cycles = append(cycles, c)
				continue
			}
			path[soname] = len(path)
			executables, c := fillIn(libToDep, soname, value, path)
			delete(path, soname)
			if c != nil {
				cycles = append(cycles, *c)
			}
			dep.executables = dep.executables.Union(executables)
		}
	}
	dep.completed = true
	mc := circle{head: depname, all: set.NewStringSet()}
	for _, c := range cycles {
		if path[c.head] < path[mc.head] {
			mc.head = c.head
		}
		mc.all = mc.all.Union(c.all)
	}
	if mc.head == depname {
		for c := range mc.all {
			libToDep[c].executables = dep.executables
		}
		return dep.executables, nil
	}
	return dep.executables, &mc
}

type circle struct {
	head string
	all set.StringSet
}
