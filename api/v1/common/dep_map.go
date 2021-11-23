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
		for lib, dependencies := range feature.ProvidedLibraries {
			for _, dep := range dependencies {
				data, ok := libToDep[dep]
				if !ok {
					data = &libDep{}
				}
				data.libraries.Add(lib)
				libToDep[dep] = data
			}
		}
		// Add executables
		for lib, execs := range feature.NeededLibrariesMap {
			if dep, ok := libToDep[lib]; ok {
				dep.executables.AddAll(execs...)
			} else {
				dep= &libDep{executables: set.NewStringSet(execs...)}
				libToDep[lib] = dep
			}
		}
	}
	// Traverse it and get the results
	depMap := make(map[string]set.StringSet)
	for k, v := range libToDep {
		depMap[k] = fillIn(libToDep, v)
	}
	return depMap
}

func fillIn(libToDep map[string]*libDep, dep *libDep) set.StringSet {
	if dep.completed {
		return dep.executables
	}
	for soname := range dep.libraries {
		if value, ok := libToDep[soname]; !ok {
			logrus.Warnf("Unresolved soname %s", soname)
		} else {
			executables := fillIn(libToDep, value)
			dep.executables = dep.executables.Union(executables)
		}
	}
	dep.completed = true
	return dep.executables
}
