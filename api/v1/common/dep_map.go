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
		for needed, execs := range feature.NeededLibrariesMap {
			if dep, ok := libToDep[needed]; ok {
				dep.executables.AddAll(execs...)
			} else {
				dep= &libDep{executables: set.NewStringSet(execs...)}
				libToDep[needed] = dep
			}
		}
	}
	ret := make(map[string]set.StringSet)
	for k, v := range libToDep {
		ret[k] = fillIn(libToDep, v)
	}
	return ret
}

func fillIn(libToDep map[string]*libDep, data *libDep) set.StringSet {
	if data.completed {
		return data.executables
	}
	for soname := range data.libraries {
		if value, ok := libToDep[soname]; !ok {
			logrus.Warnf("Unresolved soname %s", soname)
		} else {
			executables := fillIn(libToDep, value)
			data.executables = data.executables.Union(executables)
		}
	}
	data.completed = true
	return data.executables
}
