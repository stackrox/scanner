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

	"github.com/stackrox/scanner/ext/vulnsrc/rhelv2/archop"
	"github.com/stackrox/scanner/pkg/cpe"
)

type Model struct {
	// ID is only meant to be used by database implementations and should never be used for anything else.
	ID int `json:"id"`
}

type Layer struct {
	Model

	Name          string
	EngineVersion int
	Parent        *Layer
	Namespace     *Namespace
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

type RHELv2Vulnerability struct {
	Model

	Name           string        `json:"name"`
	Distribution   *Distribution `json:"distribution,omitempty"`
	Description    string        `json:"description"`
	Issued         time.Time     `json:"issued"`
	Links          string        `json:"links"`
	Severity       string        `json:"severity"`
	CVSSv3         string        `json:"cvssv3"`
	CVSSv2         string        `json:"cvssv2"`
	CPEs           []cpe.WFN     `json:"cpes"`
	Package        *Package      `json:"package"`
	FixedInVersion string        `json:"fixed_in_version"`
	ArchOperation  archop.ArchOp `json:"arch_op,omitempty"`
}

// Distribution is the accompanying system context of a package. this
// information aides in CVE detection.
//
// Distribution is modeled after the os-release file found in all linux distributions.
type Distribution struct {
	// unique ID of this distribution. this will be created as discovered by the library
	// and used for persistence and hash map indexes.
	ID string `json:"id,omitempty"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system, excluding any version information
	// and suitable for processing by scripts or usage in generated filenames. Example: "DID=fedora" or "DID=debian".
	DID string `json:"did"`
	// A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
	// identifying the operating system version, excluding any OS name information or release code name,
	// example: "16.04"
	VersionID string `json:"version_id"`
	// Optional common platform enumeration identifier
	CPE cpe.WFN `json:"cpe"`
}

type RHELv2Layer struct {
	ID   string
	Hash string
	Dist *Distribution
	Pkgs []*Package
	CPEs []string
	ParentHash string
}

type RHELv2Record struct {
	Pkg  *Package
	Dist string
	CPE  string
}

type RHELv2Components struct {
	Namespace string
	Packages  []*Package
	CPEs      []string
}

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id,omitempty"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind string `json:"kind,omitempty"`
	// if type is a binary package a source package, which built this binary package, may be present.
	// must be a pointer to support recursive type:
	Source *Package `json:"source,omitempty"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
}

func (p *Package) String() string {
	return p.Name + ":" + p.Version
}

const (
	// BINARY represents a package binary.
	BINARY = "binary"
	// SOURCE represents a source package.
	SOURCE = "source"
)

// Repository is a package repository
type Repository struct {
	ID   string  `json:"id,omitempty"`
	Name string  `json:"name,omitempty"`
	Key  string  `json:"key,omitempty"`
	URI  string  `json:"uri,omitempty"`
	CPE  cpe.WFN `json:"cpe,omitempty"`
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
