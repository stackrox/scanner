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

package v1

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
)

type Error struct {
	Message string `json:"Message,omitempty"`
}

type Layer struct {
	Name             string            `json:"Name,omitempty"`
	NamespaceName    string            `json:"NamespaceName,omitempty"`
	Path             string            `json:"Path,omitempty"`
	Headers          map[string]string `json:"Headers,omitempty"`
	ParentName       string            `json:"ParentName,omitempty"`
	Format           string            `json:"Format,omitempty"`
	IndexedByVersion int               `json:"IndexedByVersion,omitempty"`
	Features         []Feature         `json:"Features,omitempty"`
}

func LayerFromDatabaseModel(dbLayer database.Layer, withFeatures, withVulnerabilities bool) Layer {
	layer := Layer{
		Name:             dbLayer.Name,
		IndexedByVersion: dbLayer.EngineVersion,
	}

	if dbLayer.Parent != nil {
		layer.ParentName = dbLayer.Parent.Name
	}

	if dbLayer.Namespace != nil {
		layer.NamespaceName = dbLayer.Namespace.Name
	}

	if withFeatures || withVulnerabilities && dbLayer.Features != nil {
		for _, dbFeatureVersion := range dbLayer.Features {
			feature := Feature{
				Name:          dbFeatureVersion.Feature.Name,
				NamespaceName: dbFeatureVersion.Feature.Namespace.Name,
				VersionFormat: dbFeatureVersion.Feature.Namespace.VersionFormat,
				Version:       dbFeatureVersion.Version,
				AddedBy:       dbFeatureVersion.AddedBy.Name,
			}

			for _, dbVuln := range dbFeatureVersion.AffectedBy {
				vuln := Vulnerability{
					Name:          dbVuln.Name,
					NamespaceName: dbVuln.Namespace.Name,
					Description:   dbVuln.Description,
					Link:          dbVuln.Link,
					Severity:      string(dbVuln.Severity),
					Metadata:      dbVuln.Metadata,
				}

				if dbVuln.FixedBy != versionfmt.MaxVersion {
					vuln.FixedBy = dbVuln.FixedBy
				}
				feature.Vulnerabilities = append(feature.Vulnerabilities, vuln)
			}
			layer.Features = append(layer.Features, feature)
		}
	}

	return layer
}

type Namespace struct {
	Name          string `json:"Name,omitempty"`
	VersionFormat string `json:"VersionFormat,omitempty"`
}

type Vulnerability struct {
	Name          string                 `json:"Name,omitempty"`
	NamespaceName string                 `json:"NamespaceName,omitempty"`
	Description   string                 `json:"Description,omitempty"`
	Link          string                 `json:"Link,omitempty"`
	Severity      string                 `json:"Severity,omitempty"`
	Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy       string                 `json:"FixedBy,omitempty"`
	FixedIn       []Feature              `json:"FixedIn,omitempty"`
}

func (v Vulnerability) DatabaseModel() (database.Vulnerability, error) {
	severity, err := database.NewSeverity(v.Severity)
	if err != nil {
		return database.Vulnerability{}, err
	}

	var dbFeatures []database.FeatureVersion
	for _, feature := range v.FixedIn {
		dbFeature, err := feature.DatabaseModel()
		if err != nil {
			return database.Vulnerability{}, err
		}

		dbFeatures = append(dbFeatures, dbFeature)
	}

	return database.Vulnerability{
		Name:        v.Name,
		Namespace:   database.Namespace{Name: v.NamespaceName},
		Description: v.Description,
		Link:        v.Link,
		Severity:    severity,
		Metadata:    v.Metadata,
		FixedIn:     dbFeatures,
	}, nil
}

type Feature struct {
	Name            string          `json:"Name,omitempty"`
	NamespaceName   string          `json:"NamespaceName,omitempty"`
	VersionFormat   string          `json:"VersionFormat,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
	AddedBy         string          `json:"AddedBy,omitempty"`
}

func (f Feature) DatabaseModel() (fv database.FeatureVersion, err error) {
	var version string
	if f.Version == "None" {
		version = versionfmt.MaxVersion
	} else {
		err = versionfmt.Valid(f.VersionFormat, f.Version)
		if err != nil {
			return
		}
		version = f.Version
	}

	fv = database.FeatureVersion{
		Feature: database.Feature{
			Name: f.Name,
			Namespace: database.Namespace{
				Name:          f.NamespaceName,
				VersionFormat: f.VersionFormat,
			},
		},
		Version: version,
	}

	return
}

type VulnerabilityWithLayers struct {
	Vulnerability *Vulnerability `json:"Vulnerability,omitempty"`

	// This field is guaranteed to be in order only for pagination.
	// Indices from different notifications may not be comparable.
	OrderedLayersIntroducingVulnerability []OrderedLayerName `json:"OrderedLayersIntroducingVulnerability,omitempty"`

	// This field is deprecated.
	LayersIntroducingVulnerability []string `json:"LayersIntroducingVulnerability,omitempty"`
}

type OrderedLayerName struct {
	Index     int    `json:"Index"`
	LayerName string `json:"LayerName"`
}

type LayerEnvelope struct {
	Layer *Layer `json:"Layer,omitempty"`
	Error *Error `json:"Error,omitempty"`
}

type VulnerabilityEnvelope struct {
	Vulnerability   *Vulnerability   `json:"Vulnerability,omitempty"`
	Vulnerabilities *[]Vulnerability `json:"Vulnerabilities,omitempty"`
	NextPage        string           `json:"NextPage,omitempty"`
	Error           *Error           `json:"Error,omitempty"`
}

type FeatureEnvelope struct {
	Feature  *Feature   `json:"Feature,omitempty"`
	Features *[]Feature `json:"Features,omitempty"`
	Error    *Error     `json:"Error,omitempty"`
}
