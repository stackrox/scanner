package common

import (
	"github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/database"
)

type depData struct {
	support      set.StringSet
	dependencies set.StringSet
	completed    bool
}

func GetDepMap(features []database.FeatureVersion) map[string]set.StringSet {
	// Map from so to list of executables
	depMap := make(map[string]*depData)
	ret := make(map[string]set.StringSet)

	for _, feature := range features {
		for provides, dependencies := range feature.ProvidedLibraries {
			for _, dep := range dependencies {
				data, ok := depMap[dep]
				if !ok {
					data = &depData{}
				}
				data.dependencies.Add(provides)
				depMap[dep] = data
			}
		}
		for needed, execs := range feature.NeededLibrariesMap {
			if dep, ok := depMap[needed]; ok {
				dep.support.AddAll(execs...)
			} else {
				dep= &depData{support: set.NewStringSet(execs...)}
				depMap[needed] = dep
			}
		}
	}
	for _, v := range depMap {
		fillIn(depMap, v)
	}
	for k, v := range depMap {
		ret[k] = v.support
	}
	return ret
}

func fillIn(depMap map[string]*depData, data *depData) set.StringSet {
	if data.completed {
		return data.support
	}
	for soname := range data.dependencies {
		if value, ok := depMap[soname]; !ok {
			logrus.Warnf("Unresolved soname %s", soname)
		} else {
			executables := fillIn(depMap, value)
			data.support = data.support.Union(executables)
		}
	}
	data.completed = true
	return data.support
}
