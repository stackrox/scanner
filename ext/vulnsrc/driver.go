// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package vulnsrc exposes functions to dynamically register vulnerability
// sources used to update a Clair database.
package vulnsrc

import (
	"errors"
	"sync"

	"github.com/stackrox/scanner/database"
)

var (
	// ErrFilesystem is returned when a fetcher fails to interact with the local filesystem.
	ErrFilesystem = errors.New("vulnsrc: something went wrong when interacting with the fs")

	// ErrGitFailure is returned when a fetcher fails to interact with git.
	ErrGitFailure = errors.New("vulnsrc: something went wrong when interacting with git")

	updatersM sync.RWMutex
	updaters  = make(map[string]ExpectedCountAwareUpdater)
)

// UpdateResponse represents the sum of results of an update.
type UpdateResponse struct {
	FlagName        string
	FlagValue       string
	Notes           []string
	Vulnerabilities []database.Vulnerability
}

type DataStore interface {
	GetKeyValue(key string) (string, error)
}

// Updater represents anything that can fetch vulnerabilities from an external source.
type Updater interface {
	// Update gets vulnerability updates.
	Update(DataStore) (UpdateResponse, error)

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// A ExpectedCountAwareUpdater is an Updater with a ExpectedCount() method.
type ExpectedCountAwareUpdater interface {
	Updater
	// ExpectedCount returns the known number of vulnerabilities that the updater's source has.
	// Callers can compare count with the number of vulnerabilities in UpdateResponse
	// to ensure that the updater has not missed any vulnerabilities that it previously
	// used to fetch.
	ExpectedCount() int
}

type expectedCountAwareUpdater struct {
	Updater
	count int
}

func (u expectedCountAwareUpdater) ExpectedCount() int {
	return u.count
}

func wrapUpdaterWithCount(u Updater, count int) ExpectedCountAwareUpdater {
	return &expectedCountAwareUpdater{Updater: u, count: count}
}

// RegisterUpdater makes an Updater available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Updater is nil, this function panics.
func RegisterUpdater(name string, u Updater, expectedCount int) {
	if name == "" {
		panic("vulnsrc: could not register an Updater with an empty name")
	}

	if u == nil {
		panic("vulnsrc: could not register a nil Updater")
	}

	countableUpdater := wrapUpdaterWithCount(u, expectedCount)

	updatersM.Lock()
	defer updatersM.Unlock()

	if _, dup := updaters[name]; dup {
		panic("vulnsrc: RegisterUpdater called twice for " + name)
	}

	updaters[name] = countableUpdater
}

// Updaters returns the list of the registered Updaters.
func Updaters() map[string]ExpectedCountAwareUpdater {
	updatersM.RLock()
	defer updatersM.RUnlock()

	ret := make(map[string]ExpectedCountAwareUpdater)
	for k, v := range updaters {
		ret[k] = v
	}

	return ret
}
