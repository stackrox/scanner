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
)

type Model struct {
	// ID is only meant to be used by database implementations and should never be used for anything else.
	ID int `json:",omitempty"`
}

type Layer struct {
	Model `json:",omitempty"`

	Name          string           `json:",omitempty"`
	EngineVersion int              `json:",omitempty"`
	Parent        *Layer           `json:",omitempty"`
	Namespace     *Namespace       `json:",omitempty"`
	Features      []FeatureVersion `json:",omitempty"`
}

type Namespace struct {
	Model `json:",omitempty"`

	Name          string `json:",omitempty"`
	VersionFormat string `json:",omitempty"`
}

type Feature struct {
	Model `json:",omitempty"`

	Name       string    `json:",omitempty"`
	Namespace  Namespace `json:",omitempty"`
	SourceType string    `json:",omitempty"`
	Location   string    `json:",omitempty"`
}

type FeatureVersion struct {
	Model `json:",omitempty"`

	Feature    Feature         `json:",omitempty"`
	Version    string          `json:",omitempty"`
	AffectedBy []Vulnerability `json:",omitempty"`

	// For output purposes. Only make sense when the feature version is in the context of an image.
	AddedBy Layer `json:",omitempty"`
}

type Vulnerability struct {
	Model `json:",omitempty"`

	Name      string    `json:",omitempty"`
	Namespace Namespace `json:",omitempty"`

	Description string   `json:",omitempty"`
	Link        string   `json:",omitempty"`
	Severity    Severity `json:",omitempty"`

	Metadata MetadataMap `json:",omitempty"`

	FixedIn                        []FeatureVersion `json:",omitempty"`
	LayersIntroducingVulnerability []Layer          `json:",omitempty"`

	// For output purposes. Only make sense when the vulnerability
	// is already about a specific Feature/FeatureVersion.
	FixedBy string `json:",omitempty"`

	SubCVEs []string `json:",omitempty"`
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
