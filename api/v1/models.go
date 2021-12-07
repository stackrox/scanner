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
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/api/v1/common"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/rhel"
	namespaces "github.com/stackrox/scanner/pkg/wellknownnamespaces"
)

// These are possible package prefixes or suffixes. Package managers sometimes annotate
// the packages with these e.g. urllib-python
var possiblePythonPrefixesOrSuffixes = []string{
	"python", "python2", "python3",
}

// Linux and kernel packages that are not applicable to images
var kernelPrefixes = []string{
	"linux",
	"kernel",
}

// Error is a scanning error.
type Error struct {
	Message string `json:"Message,omitempty"`
}

// Layer is an image layer.
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

// getLanguageData returns all application (language) features in the given layer.
// This data includes features which were introduced in lower (parent) layers.
// Since an image is based on a layered-filesystem, this function recognizes when files/locations
// have been removed, and does not return features from files from lower (parent) levels which have been deleted
// in higher (child) levels.
//
// A returned feature's AddedBy is the first (parent) layer that introduced the feature. For example,
// if a file was modified between layers in a way that the features it describes are untouched
// (ex: chown, touch), then the higher layer's features from that file are unused.
//
// A known issue is if a file defines multiple features, and the file is modified between layers in a way
// that does affect the features it describes (adds, updates, or removes features), which is currently only a
// concern for the Java source type. However, this event is unlikely, which is why it is not considered at this time.
func getLanguageData(db database.Datastore, layerName, lineage string, uncertifiedRHEL bool) ([]database.FeatureVersion, error) {
	layersToComponents, err := db.GetLayerLanguageComponents(layerName, lineage, &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil {
		return nil, err
	}

	type languageFeatureValue struct {
		name, version, layer string
	}
	languageFeatureMap := make(map[string]languageFeatureValue)
	var removedLanguageComponentLocations []string
	var features []database.FeatureVersion

	// ignoredLanguageComponents keeps track of the language components that were ignored because
	// they came from the package manager. This is from lowest (base image) up to the highest because
	// modifications to the files in later layers may not have a package manager change associated (e.g. chown a JAR)
	ignoredLanguageComponents := make(map[string]languageFeatureValue)
	for _, layerToComponent := range layersToComponents {
		for _, c := range layerToComponent.Components {
			if c.FromPackageManager {
				ignoredLanguageComponents[c.Location] = languageFeatureValue{
					name:    c.Name,
					version: c.Version,
				}
			}
		}
	}

	// Loop from highest layer to lowest.
	for i := len(layersToComponents) - 1; i >= 0; i-- {
		layerToComponents := layersToComponents[i]

		// Ignore components which were removed in higher layers.
		components := layerToComponents.Components[:0]
		for _, c := range layerToComponents.Components {
			if c.FromPackageManager {
				continue
			}
			if lfv, ok := ignoredLanguageComponents[c.Location]; ok && lfv.name == c.Name && lfv.version == c.Version {
				continue
			}
			include := true
			for _, removedLocation := range removedLanguageComponentLocations {
				if strings.HasPrefix(c.Location, removedLocation) {
					include = false
					break
				}
			}

			if include {
				components = append(components, c)
			}
		}

		newFeatures := cpe.CheckForVulnerabilities(layerToComponents.Layer, components)
		for _, fv := range newFeatures {
			location := fv.Feature.Location
			featureValue := languageFeatureValue{
				name:    fv.Feature.Name,
				version: fv.Version,
				layer:   layerToComponents.Layer,
			}
			if existing, ok := languageFeatureMap[location]; ok {
				if featureValue.name != existing.name || featureValue.version != existing.version {
					// The contents at this location have changed between layers.
					// Use the higher layer's.
					continue
				}
			}

			features = append(features, fv)
			languageFeatureMap[location] = featureValue
		}

		removedLanguageComponentLocations = append(removedLanguageComponentLocations, layerToComponents.Removed...)
	}

	// We want to output the features in layer-order, so we must reverse the feature slice.
	// At the same time, we want to be sure to remove any repeat features that were not filtered previously
	// (this would be due us detecting a feature was introduced into the image at a lower level than originally thought).
	filtered := make([]database.FeatureVersion, 0, len(features))
	for i := len(features) - 1; i >= 0; i-- {
		feature := features[i]

		featureValue := languageFeatureMap[feature.Feature.Location]
		if feature.AddedBy.Name == featureValue.layer {
			filtered = append(filtered, feature)
		}
	}

	return filtered, nil
}

// VulnerabilityFromDatabaseModel converts the given database.Vulnerability into a Vulnerability.
func VulnerabilityFromDatabaseModel(dbVuln database.Vulnerability) Vulnerability {
	vuln := Vulnerability{
		Name:          dbVuln.Name,
		NamespaceName: dbVuln.Namespace.Name,
		Description:   dbVuln.Description,
		Link:          dbVuln.Link,
		Severity:      string(databaseVulnToSeverity(dbVuln)),
		Metadata:      dbVuln.Metadata,
	}
	if dbVuln.FixedBy != versionfmt.MaxVersion {
		vuln.FixedBy = dbVuln.FixedBy
	}
	return vuln
}

func featureFromDatabaseModel(dbFeatureVersion database.FeatureVersion, uncertified bool, depMap map[string]set.StringSet) *Feature {
	version := dbFeatureVersion.Version
	if version == versionfmt.MaxVersion {
		version = "None"
	}

	addedBy := dbFeatureVersion.AddedBy.Name
	if uncertified {
		addedBy = rhel.GetOriginalLayerName(addedBy)
	}

	executables, legacyExecutables := createExecutablesFromDependencies(dbFeatureVersion.ExecutableToDependencies, depMap)
	return &Feature{
		Name:                          dbFeatureVersion.Feature.Name,
		NamespaceName:                 dbFeatureVersion.Feature.Namespace.Name,
		VersionFormat:                 stringutils.OrDefault(dbFeatureVersion.Feature.SourceType, dbFeatureVersion.Feature.Namespace.VersionFormat),
		Version:                       version,
		AddedBy:                       addedBy,
		Location:                      dbFeatureVersion.Feature.Location,
		DeprecatedProvidedExecutables: legacyExecutables,
		Executables:                   executables,
	}
}

func toFeatureNameVersions(keys set.StringSet) []*v1.FeatureNameVersion {
	if len(keys) == 0 {
		return nil
	}
	features := make([]*v1.FeatureNameVersion, 0, len(keys))
	for k := range keys {
		featureKey, err := common.ParseFeatureNameVersion(k)
		utils.Should(err)
		features = append(features, &v1.FeatureNameVersion{Name: featureKey.Name, Version: featureKey.Version})
	}
	return features
}

func dedupeVersionMatcher(v1, v2 string) bool {
	if v1 == v2 {
		return true
	}
	return strings.HasPrefix(v2, v1)
}

func dedupeFeatureNameMatcher(feature Feature, osFeature Feature) bool {
	if feature.Name == osFeature.Name {
		return true
	}

	if feature.VersionFormat == component.PythonSourceType.String() {
		for _, ext := range possiblePythonPrefixesOrSuffixes {
			if feature.Name == strings.TrimPrefix(osFeature.Name, fmt.Sprintf("%s-", ext)) {
				return true
			}
			if feature.Name == strings.TrimSuffix(osFeature.Name, fmt.Sprintf("-%s", ext)) {
				return true
			}
		}
	}
	return false
}

func shouldDedupeLanguageFeature(feature Feature, osFeatures []Feature) bool {
	// Can probably sort this and it'll be faster
	for _, osFeature := range osFeatures {
		if dedupeFeatureNameMatcher(feature, osFeature) && dedupeVersionMatcher(feature.Version, osFeature.Version) {
			return true
		}
	}
	return false
}

// addLanguageVulns adds language-based features into the given layer.
// Assumes layer is not nil.
func addLanguageVulns(db database.Datastore, layer *Layer, lineage string, uncertifiedRHEL bool) {
	// Add Language Features
	languageFeatureVersions, err := getLanguageData(db, layer.Name, lineage, uncertifiedRHEL)
	if err != nil {
		log.Errorf("error getting language data: %v", err)
		return
	}

	var languageFeatures []Feature
	for _, dbFeatureVersion := range languageFeatureVersions {
		feature := featureFromDatabaseModel(dbFeatureVersion, uncertifiedRHEL, nil)
		if !shouldDedupeLanguageFeature(*feature, layer.Features) {
			updateFeatureWithVulns(feature, dbFeatureVersion.AffectedBy, language.ParserName)
			languageFeatures = append(languageFeatures, *feature)
		}
	}
	layer.Features = append(layer.Features, languageFeatures...)
}

func hasKernelPrefix(name string) bool {
	for _, prefix := range kernelPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// LayerFromDatabaseModel returns the scan data for the given layer based on the data in the given datastore.
func LayerFromDatabaseModel(db database.Datastore, dbLayer database.Layer, lineage string, opts *database.DatastoreOptions, depMap map[string]set.StringSet) (Layer, []Note, error) {
	withFeatures := opts.GetWithFeatures()
	withVulnerabilities := opts.GetWithVulnerabilities()
	uncertifiedRHEL := opts.GetUncertifiedRHEL()
	layer := Layer{
		Name:             dbLayer.Name,
		IndexedByVersion: dbLayer.EngineVersion,
	}

	if dbLayer.Parent != nil {
		layer.ParentName = dbLayer.Parent.Name
	}

	var notes []Note
	if dbLayer.Namespace != nil {
		layer.NamespaceName = dbLayer.Namespace.Name

		if namespaces.KnownStaleNamespaces.Contains(layer.NamespaceName) {
			notes = append(notes, OSCVEsStale)
		} else if !namespaces.KnownSupportedNamespaces.Contains(layer.NamespaceName) {
			notes = append(notes, OSCVEsUnavailable)
		}
	} else {
		notes = append(notes, OSCVEsUnavailable)
	}

	if !env.LanguageVulns.Enabled() {
		notes = append(notes, LanguageCVEsUnavailable)
	}
	if uncertifiedRHEL {
		// Uncertified results were requested.
		notes = append(notes, CertifiedRHELScanUnavailable)
	}

	if (withFeatures || withVulnerabilities) && (dbLayer.Features != nil || namespaces.IsRHELNamespace(layer.NamespaceName)) {
		for _, dbFeatureVersion := range dbLayer.Features {
			feature := featureFromDatabaseModel(dbFeatureVersion, opts.GetUncertifiedRHEL(), depMap)

			if hasKernelPrefix(feature.Name) {
				continue
			}

			updateFeatureWithVulns(feature, dbFeatureVersion.AffectedBy, dbFeatureVersion.Feature.Namespace.VersionFormat)
			layer.Features = append(layer.Features, *feature)
		}
		if !uncertifiedRHEL && namespaces.IsRHELNamespace(layer.NamespaceName) {
			certified, err := addRHELv2Vulns(db, &layer)
			if err != nil {
				return layer, notes, err
			}
			if !certified {
				// Client expected certified results, but they are unavailable.
				notes = append(notes, CertifiedRHELScanUnavailable)
			}
		}
		if env.LanguageVulns.Enabled() {
			addLanguageVulns(db, &layer, lineage, uncertifiedRHEL)
		}
	}

	return layer, notes, nil
}

func updateFeatureWithVulns(feature *Feature, dbVulns []database.Vulnerability, versionFormat string) {
	allVulnsFixedBy := feature.FixedBy
	for _, dbVuln := range dbVulns {
		vuln := VulnerabilityFromDatabaseModel(dbVuln)
		feature.Vulnerabilities = append(feature.Vulnerabilities, vuln)

		// If at least one vulnerability is not fixable, then we mark it the component as not fixable.
		if vuln.FixedBy == "" {
			continue
		}

		higherVersion, err := versionfmt.GetHigherVersion(versionFormat, vuln.FixedBy, allVulnsFixedBy)
		if err != nil {
			log.Errorf("comparing feature versions for %s: %v", feature.Name, err)
			continue
		}
		allVulnsFixedBy = higherVersion
	}
	feature.FixedBy = allVulnsFixedBy
}

// Namespace is the image's base OS.
type Namespace struct {
	Name          string `json:"Name,omitempty"`
	VersionFormat string `json:"VersionFormat,omitempty"`
}

// Vulnerability defines a vulnerability.
type Vulnerability struct {
	Name          string                 `json:"Name,omitempty"`
	NamespaceName string                 `json:"NamespaceName,omitempty"`
	Description   string                 `json:"Description,omitempty"`
	Link          string                 `json:"Link,omitempty"`
	Severity      string                 `json:"Severity,omitempty"`
	Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy       string                 `json:"FixedBy,omitempty"`
}

// Feature is a scanned package in an image.
type Feature struct {
	Name            string          `json:"Name,omitempty"`
	NamespaceName   string          `json:"NamespaceName,omitempty"`
	VersionFormat   string          `json:"VersionFormat,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
	AddedBy         string          `json:"AddedBy,omitempty"`
	Location        string          `json:"Location,omitempty"`
	FixedBy         string          `json:"FixedBy,omitempty"`
	// Deprecated: ProvidedExecutables
	DeprecatedProvidedExecutables []string         `json:"ProvidedExecutables,omitempty"`
	Executables                   []*v1.Executable `json:"Executables,omitempty"`
}

// DatabaseModel returns a database.FeatureVersion based on the caller Feature.
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

// LayerEnvelope envelopes complete scan data to return to the client.
type LayerEnvelope struct {
	Layer *Layer `json:"Layer,omitempty"`
	Notes []Note `json:"Notes,omitempty"`
	Error *Error `json:"Error,omitempty"`
}

// Note defines scanning notes.
type Note int

const (
	// OSCVEsUnavailable labels scans of images with unknown namespaces or obsolete namespaces.
	OSCVEsUnavailable Note = iota
	// OSCVEsStale labels scans of images with namespaces whose CVEs are known to be stale.
	OSCVEsStale
	// LanguageCVEsUnavailable labels scans of images with without language CVEs.
	// This is typically only populated when language CVEs are not enabled.
	LanguageCVEsUnavailable
	// CertifiedRHELScanUnavailable labels scans of RHEL-based images out-of-scope
	// of the Red Hat Certification program.
	// These images were made before June 2020, and they are missing content manifest JSON files.
	CertifiedRHELScanUnavailable
)

// VulnerabilityEnvelope envelopes complete vulnerability data to return to the client.
type VulnerabilityEnvelope struct {
	Vulnerability   *Vulnerability   `json:"Vulnerability,omitempty"`
	Vulnerabilities *[]Vulnerability `json:"Vulnerabilities,omitempty"`
	NextPage        string           `json:"NextPage,omitempty"`
	Error           *Error           `json:"Error,omitempty"`
}

// FeatureEnvelope envelopes complete feature data to return to the client.
type FeatureEnvelope struct {
	Feature  *Feature   `json:"Feature,omitempty"`
	Features *[]Feature `json:"Features,omitempty"`
	Error    *Error     `json:"Error,omitempty"`
}
