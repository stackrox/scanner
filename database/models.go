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
	"strconv"
	"strings"
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
	ID string `json:"id"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system, excluding any version information
	// and suitable for processing by scripts or usage in generated filenames. Example: "DID=fedora" or "DID=debian".
	DID string `json:"did"`
	// A string identifying the operating system.
	// example: "Ubuntu"
	Name string `json:"name"`
	// A string identifying the operating system version, excluding any OS name information,
	// possibly including a release code name, and suitable for presentation to the user.
	// example: "16.04.6 LTS (Xenial Xerus)"
	Version string `json:"version"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system release code name,
	// excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames
	// example: "xenial"
	VersionCodeName string `json:"version_code_name"`
	// A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
	// identifying the operating system version, excluding any OS name information or release code name,
	// example: "16.04"
	VersionID string `json:"version_id"`
	// A string identifying the OS architecture
	// example: "x86_64"
	Arch string `json:"arch"`
	// Optional common platform enumeration identifier
	CPE cpe.WFN `json:"cpe"`
	// A pretty operating system name in a format suitable for presentation to the user.
	// May or may not contain a release code name or OS version of some kind, as suitable. If not set, defaults to "PRETTY_NAME="Linux"".
	// example: "PRETTY_NAME="Fedora 17 (Beefy Miracle)"".
	PrettyName string `json:"pretty_name"`
}

type Package struct {
	// unique ID of this package. this will be created as discovered by the library
	// and used for persistence and hash map indexes
	ID string `json:"id"`
	// the name of the package
	Name string `json:"name"`
	// the version of the package
	Version string `json:"version"`
	// type of package. currently expectations are binary or source
	Kind string `json:"kind,omitempty"`
	// if type is a binary package a source package maybe present which built this binary package.
	// must be a pointer to support recursive type:
	Source *Package `json:"source,omitempty"`
	// the file system path or prefix where this package resides
	PackageDB string `json:"-"`
	// a hint on which repository this package was downloaded from
	RepositoryHint string `json:"-"`
	// NormalizedVersion is a representation of a version string that's
	// correctly ordered when compared with other representations from the same
	// producer.
	NormalizedVersion Version `json:"normalized_version,omitempty"`
	// Module and stream which this package is part of
	Module string `json:"module,omitempty"`
	// Package architecture
	Arch string `json:"arch,omitempty"`
	// CPE name for package
	CPE cpe.WFN `json:"cpe,omitempty"`
}

// Version describes a revision of some sort that is ordered correctly within
// its "Kind".
//
// Versions of different kinds do not have any sensible ordering.
type Version struct {
	Kind string
	V    [10]int32
}

// VersionSort returns a function suitable for passing to sort.Slice or
// sort.SliceStable.
func VersionSort(vs []Version) func(int, int) bool {
	return func(i, j int) bool { return vs[i].Compare(&vs[j]) == -1 }
}

// MarshalText implments encoding.TextMarshaler.
func (v *Version) MarshalText() ([]byte, error) {
	if v.Kind == "" {
		return nil, nil
	}
	var buf bytes.Buffer
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer
	buf.WriteString(v.Kind)
	buf.WriteByte(':')
	for i := 0; i < 10; i++ {
		if i != 0 {
			buf.WriteByte('.')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	return buf.Bytes(), nil
}

// UnmarshalText implments encoding.TextUnmarshaler.
func (v *Version) UnmarshalText(text []byte) (err error) {
	idx := bytes.IndexByte(text, ':')
	if idx == -1 {
		return nil
	}
	if v == nil {
		*v = Version{}
	}
	v.Kind = string(text[:idx])
	var n int64
	for i, b := range bytes.Split(text[idx+1:], []byte(".")) {
		n, err = strconv.ParseInt(string(b), 10, 32)
		if err != nil {
			return err
		}
		v.V[i] = int32(n)
	}
	return nil
}

func (v *Version) String() string {
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	if v.V[0] != 0 {
		buf.Write(strconv.AppendInt(b, int64(v.V[0]), 10))
		buf.WriteByte('!')
	}
	var f, l int
	for i := 1; i < 10; i++ {
		if v.V[i] != 0 {
			if f == 0 {
				f = i
			}
			l = i
		}
	}
	// If we didn't set the offsets in the above loop, bump to make them
	// absolute to the version array.
	if f == 0 {
		f++
	}
	if l == 0 {
		l++
	}
	for i, n := range v.V[f : l+1] {
		if i != 0 {
			buf.WriteByte('.')
		}
		buf.Write(strconv.AppendInt(b, int64(n), 10))
	}

	return buf.String()
}

// Compare returns an integer describing the relationship of two Versions.
//
// The result will be 0 if a==b, -1 if a < b, and +1 if a > b. If the Versions
// are of different kinds, the Kinds will be compared lexographically.
func (v *Version) Compare(x *Version) int {
	if v.Kind != x.Kind {
		return strings.Compare(v.Kind, x.Kind)
	}
	for i := 0; i < 10; i++ {
		if v.V[i] > x.V[i] {
			return 1
		}
		if v.V[i] < x.V[i] {
			return -1
		}
	}
	return 0
}

// Range is a half-open interval of two Versions.
//
// In the usual notation, it is: [Lower, Upper)
type Range struct {
	Lower Version `json:"["`
	Upper Version `json:")"`
}

// Contains reports whether the Version falls within the Range.
func (r *Range) Contains(v *Version) bool {
	if r == nil {
		return false
	}
	// Lower <= v && Upper > v
	return r.Lower.Compare(v) != 1 && r.Upper.Compare(v) == 1
}
