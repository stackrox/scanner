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

package database

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/stackrox/scanner/pkg/rhelv2/archop"
)

type Model struct {
	// ID is only meant to be used by database implementations and should never be used for anything else.
	ID int `json:"id,omitempty"`
}

type Layer struct {
	Model

	Name          string
	EngineVersion int
	Parent        *Layer
	Namespace     *Namespace
	Distroless    bool
	Features      []FeatureVersion
}

type Namespace struct {
	Model

	Name          string
	VersionFormat string
}

type Feature struct {
	Model

	Name       string
	Namespace  Namespace
	SourceType string
	Location   string
}

type FeatureVersion struct {
	Model

	Feature    Feature
	Version    string
	AffectedBy []Vulnerability

	// For output purposes. Only make sense when the feature version is in the context of an image.
	AddedBy Layer
}

type Vulnerability struct {
	Model

	Name      string
	Namespace Namespace

	Description string
	Link        string
	Severity    Severity

	Metadata MetadataMap

	FixedIn                        []FeatureVersion
	LayersIntroducingVulnerability []Layer

	// For output purposes. Only make sense when the vulnerability
	// is already about a specific Feature/FeatureVersion.
	FixedBy string `json:",omitempty"`

	SubCVEs []string
}

type MetadataMap map[string]interface{}

func (mm *MetadataMap) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	// github.com/lib/pq decodes TEXT/VARCHAR fields into strings.
	val, ok := value.(string)
	if !ok {
		panic("got type other than []byte from database")
	}
	return json.Unmarshal([]byte(val), mm)
}

func (mm *MetadataMap) Value() (driver.Value, error) {
	json, err := json.Marshal(*mm)
	return string(json), err
}

// TODO: the following is adapted form claircore

type RHELv2Vulnerability struct {
	Model

	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Issued         time.Time     `json:"issued"`
	Updated        time.Time     `json:"updated"`
	Links          string        `json:"links"`
	Severity       string        `json:"severity"`
	CVSSv3         string        `json:"cvssv3"`
	CVSSv2         string        `json:"cvssv2"`
	CPEs           []string      `json:"cpes"`
	Package        *Package      `json:"package"`
	FixedInVersion string        `json:"fixed_in_version"`
	ArchOperation  archop.ArchOp `json:"arch_op,omitempty"`
}

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id,omitempty"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
}

func (p *Package) String() string {
	return p.Name + ":" + p.Version
}
