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
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"time"

	archop "github.com/quay/claircore"
)

type Model struct {
	// ID is only meant to be used by database implementations and should never be used for anything else.
	ID int `json:"id,omitempty" hash:"ignore"`
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

///////////////////////////////////////////////////
// BEGIN
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

type RHELv2Vulnerability struct {
	Model

	Name         string               `json:"name"`
	Description  string               `json:"description"`
	Issued       time.Time            `json:"issued"`
	Updated      time.Time            `json:"updated"`
	Link         string               `json:"link"`
	Severity     string               `json:"severity"`
	CVSSv3       string               `json:"cvssv3,omitempty"`
	CVSSv2       string               `json:"cvssv2,omitempty"`
	CPEs         []string             `json:"cpes" hash:"set"`
	PackageInfos []*RHELv2PackageInfo `json:"package_info" hash:"set"`
	Title        string               `json:"title"`
}

type RHELv2PackageInfo struct {
	Packages       []*RHELv2Package `json:"package" hash:"set"`
	FixedInVersion string           `json:"fixed_in_version"`
	ArchOperation  archop.ArchOp    `json:"arch_op,omitempty"`
}

type RHELv2Package struct {
	Model

	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Module  string `json:"module,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

func (p *RHELv2Package) String() string {
	return strings.Join([]string{p.Name, p.Version, p.Module, p.Arch}, ":")
}

type RHELv2Layer struct {
	Model

	Hash       string
	ParentHash string
	Dist       string
	Pkgs       []*RHELv2Package
	CPEs       []string
}

type RHELv2Components struct {
	Dist     string
	Packages []*RHELv2Package
	CPEs     []string
}

func (r *RHELv2Components) String() string {
	var buf bytes.Buffer
	buf.WriteString(r.Dist)
	buf.WriteString(" - ")
	buf.WriteString("[ ")
	for _, cpe := range r.CPEs {
		buf.WriteString(cpe)
		buf.WriteString(" ")
	}
	buf.WriteString("]")
	buf.WriteString("[ ")
	for _, pkg := range r.Packages {
		buf.WriteString(pkg.String())
		buf.WriteString(" ")
	}
	buf.WriteString("]")

	return buf.String()
}

// RHELv2PackageEnv contains a RHELv2Package plus
// data about the environment surrounding a particular package.
type RHELv2PackageEnv struct {
	Pkg     *RHELv2Package
	AddedBy string
	CPEs    []string
}

// RHELv2Record is used for querying RHELv2 vulnerabilities from the database.
type RHELv2Record struct {
	Pkg *RHELv2Package
	CPE string
}

// ContentManifest structure is based on file provided by OSBS
// The struct stores content metadata about the image
type ContentManifest struct {
	ContentSets []string         `json:"content_sets"`
	Metadata    ManifestMetadata `json:"metadata"`
}

// ManifestMetadata struct holds additional metadata about image
type ManifestMetadata struct {
	ImageLayerIndex int `json:"image_layer_index"`
}

///////////////////////////////////////////////////
// END
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////
