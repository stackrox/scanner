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
	"strconv"
	"strings"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/cpe"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/language"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/types"
	"github.com/stackrox/scanner/pkg/wellknownnamespaces"
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
func getLanguageData(db database.Datastore, layerName string) ([]database.FeatureVersion, error) {
	layersToComponents, err := db.GetLayerLanguageComponents(layerName)
	if err != nil {
		return nil, err
	}

	type languageFeatureValue struct {
		name, version, layer string
	}
	languageFeatureMap := make(map[string]languageFeatureValue)
	var removedLanguageComponentLocations []string
	var features []database.FeatureVersion

	// Loop from highest layer to lowest.
	for i := len(layersToComponents) - 1; i >= 0; i-- {
		layerToComponents := layersToComponents[i]

		// Ignore components which were removed in higher layers.
		components := layerToComponents.Components[:0]
		for _, c := range layerToComponents.Components {
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

func VulnerabilityFromDatabaseModel(dbVuln database.Vulnerability) Vulnerability {
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
	return vuln
}

func featureFromDatabaseModel(dbFeatureVersion database.FeatureVersion) *Feature {
	version := dbFeatureVersion.Version
	if version == versionfmt.MaxVersion {
		version = "None"
	}

	return &Feature{
		Name:          dbFeatureVersion.Feature.Name,
		NamespaceName: dbFeatureVersion.Feature.Namespace.Name,
		VersionFormat: stringutils.OrDefault(dbFeatureVersion.Feature.SourceType, dbFeatureVersion.Feature.Namespace.VersionFormat),
		Version:       version,
		AddedBy:       dbFeatureVersion.AddedBy.Name,
		Location:      dbFeatureVersion.Feature.Location,
	}
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
func addLanguageVulns(db database.Datastore, layer *Layer) {
	// Add Language Features
	languageFeatureVersions, err := getLanguageData(db, layer.Name)
	if err != nil {
		log.Errorf("error getting language data: %v", err)
		return
	}

	var languageFeatures []Feature
	for _, dbFeatureVersion := range languageFeatureVersions {
		feature := featureFromDatabaseModel(dbFeatureVersion)
		if !shouldDedupeLanguageFeature(*feature, layer.Features) {
			updateFeatureWithVulns(feature, dbFeatureVersion.AffectedBy, language.ParserName)
			languageFeatures = append(languageFeatures, *feature)
		}
	}
	layer.Features = append(layer.Features, languageFeatures...)
}

func LayerFromDatabaseModel(db database.Datastore, dbLayer database.Layer, withFeatures, withVulnerabilities bool) (Layer, []Note, error) {
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

		if wellknownnamespaces.KnownStaleNamespaces.Contains(layer.NamespaceName) {
			notes = append(notes, OSCVEsStale)
		} else if !wellknownnamespaces.KnownSupportedNamespaces.Contains(layer.NamespaceName) {
			notes = append(notes, OSCVEsUnavailable)
		}
	} else {
		notes = append(notes, OSCVEsUnavailable)
	}

	if !env.LanguageVulns.Enabled() {
		notes = append(notes, LanguageCVEsUnavailable)
	}

	if (withFeatures || withVulnerabilities) && (dbLayer.Features != nil || strings.HasPrefix(layer.NamespaceName, "rhel")) {
	OUTER:
		for _, dbFeatureVersion := range dbLayer.Features {
			feature := featureFromDatabaseModel(dbFeatureVersion)

			for _, prefix := range kernelPrefixes {
				if strings.HasPrefix(feature.Name, prefix) {
					continue OUTER
				}
			}

			updateFeatureWithVulns(feature, dbFeatureVersion.AffectedBy, dbFeatureVersion.Feature.Namespace.VersionFormat)
			layer.Features = append(layer.Features, *feature)
		}
		if strings.HasPrefix(layer.NamespaceName, "rhel") {
			if err := addRHELv2Vulns(db, &layer); err != nil {
				return layer, notes, err
			}
		}
		if env.LanguageVulns.Enabled() {
			addLanguageVulns(db, &layer)
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

///////////////////////////////////////////////////
// BEGIN
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

func addRHELv2Vulns(db database.Datastore, layer *Layer) error {
	layers, err := db.GetRHELv2Layers(layer.Name)
	if err != nil {
		return err
	}

	shareCPEs(layers)

	pkgEnvs, records := getRHELv2PkgData(layers)

	vulns, err := db.GetRHELv2Vulnerabilities(records)
	if err != nil {
		return err
	}

	for _, pkgEnv := range pkgEnvs {
		pkg := pkgEnv.Pkg

		feature := Feature{
			Name:          pkg.Name,
			NamespaceName: layer.NamespaceName,
			VersionFormat: rpm.ParserName,
			Version:       pkg.Version,
			AddedBy:       pkgEnv.AddedBy,
			Location:      "var/lib/rpm/Packages", // TODO: Fill out?
		}

		pkgVersion := rpmVersion.NewVersion(pkg.Version)
		pkgArch := pkg.Arch
		fixedBy := pkgVersion

		// Database query results need more filtering.
		// Need to ensure:
		// 1. The package's version is less than the vuln's fixed-in version, if present.
		// 2. The ArchOperation passes.
		for _, vuln := range vulns[pkg.ID] {
			// Assume the vulnerability is not fixed.
			// In that case, all versions are affected.
			affectedVersion := true
			var vulnVersion *rpmVersion.Version
			if vuln.FixedInVersion != "" {
				// The vulnerability is fixed. Determine if this package is affected.
				vulnVersion = rpmVersionPtr(rpmVersion.NewVersion(vuln.FixedInVersion))
				affectedVersion = pkgVersion.LessThan(*vulnVersion)
			}

			// Compare the package's architecture to the affected architecture.
			affectedArch := vuln.ArchOperation.Cmp(pkgArch, vuln.Package.Arch)

			if affectedVersion && affectedArch {
				feature.Vulnerabilities = append(feature.Vulnerabilities, rhelv2ToVulnerability(vuln, feature.NamespaceName))

				if vulnVersion != nil && vulnVersion.GreaterThan(fixedBy) {
					fixedBy = *vulnVersion
				}
			}
		}

		if fixedBy.GreaterThan(pkgVersion) {
			feature.FixedBy = fixedBy.String()
		}

		layer.Features = append(layer.Features, feature)
	}

	return nil
}

func rpmVersionPtr(ver rpmVersion.Version) *rpmVersion.Version {
	return &ver
}

// shareRepos takes repository definition and share it with other layers
// where repositories are missing
func shareCPEs(layers []*database.RHELv2Layer) {
	// User's layers build on top of Red Hat images doesn't have a repository definition.
	// We need to share CPE repo definition to all layer where CPEs are missing
	var previousCPEs []string
	for i := 0; i < len(layers); i++ {
		if len(layers[i].CPEs) != 0 {
			previousCPEs = layers[i].CPEs
		} else {
			layers[i].CPEs = append(layers[i].CPEs, previousCPEs...)
		}
	}

	// Tha same thing has to be done in reverse
	// example:
	//   Red Hat's base images doesn't have repository definition
	//   We need to get them from layer[i+1]
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i].CPEs) != 0 {
			previousCPEs = layers[i].CPEs
		} else {
			layers[i].CPEs = append(layers[i].CPEs, previousCPEs...)
		}
	}
}

func getRHELv2PkgData(layers []*database.RHELv2Layer) (map[int]*database.RHELv2PackageEnv, []*database.RHELv2Record) {
	pkgEnvs := make(map[int]*database.RHELv2PackageEnv)

	// Find all packages that were ever added to the image
	// labelled with the layer hash that introduced it.
	for _, layer := range layers {
		for _, pkg := range layer.Pkgs {
			if _, ok := pkgEnvs[pkg.ID]; !ok {
				pkgEnvs[pkg.ID] = &database.RHELv2PackageEnv{
					Pkg:     pkg,
					AddedBy: layer.Hash,
					CPEs:    layer.CPEs,
				}
			}
		}
	}

	// Look for the packages that still remain in the final image.
	// Loop from highest layer to base in search of the latest version of
	// the packages database.
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i].Pkgs) != 0 {
			// Found the latest version of `var/lib/rpm/Packages`
			// This has the final version of all the packages in this image.
			finalPkgs := set.NewIntSet()
			for _, pkg := range layers[i].Pkgs {
				finalPkgs.Add(pkg.ID)
			}

			for pkgID := range pkgEnvs {
				// Remove packages that were in lower layers, but not at the highest.
				if !finalPkgs.Contains(pkgID) {
					delete(pkgEnvs, pkgID)
				}
			}

			break
		}
	}

	// Create a record for each pkgEnvironment for each CPE.
	var records []*database.RHELv2Record

	for _, pkgEnv := range pkgEnvs {
		if len(pkgEnv.CPEs) == 0 {
			records = append(records, &database.RHELv2Record{
				Pkg: pkgEnv.Pkg,
			})

			continue
		}

		for _, cpe := range pkgEnv.CPEs {
			records = append(records, &database.RHELv2Record{
				Pkg: pkgEnv.Pkg,
				CPE: cpe,
			})
		}
	}

	return pkgEnvs, records
}

func rhelv2ToVulnerability(vuln *database.RHELv2Vulnerability, namespace string) Vulnerability {
	var cvss2 types.MetadataCVSSv2
	if vuln.CVSSv2 != "" {
		scoreStr, vector := stringutils.Split2(vuln.CVSSv2, "/")
		score, err := strconv.ParseFloat(scoreStr, 64)
		if err != nil {
			log.Errorf("Unable to parse CVSSv2 score from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv2)
		} else {
			cvss2Ptr, err := types.ConvertCVSSv2(vector)
			if err != nil {
				log.Errorf("Unable to parse CVSSv2 vector from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv2)
			} else {
				cvss2 = *cvss2Ptr
				if score != cvss2Ptr.Score {
					log.Warnf("Given CVSSv2 score and computed score differ for RHEL vulnerability %s: %f != %f. Using given score...", vuln.Name, score, cvss2Ptr.Score)
					cvss2Ptr.Score = score
				}
			}
		}
	}

	var cvss3 types.MetadataCVSSv3
	if vuln.CVSSv3 != "" {
		scoreStr, vector := stringutils.Split2(vuln.CVSSv3, "/")
		score, err := strconv.ParseFloat(scoreStr, 64)
		if err != nil {
			log.Errorf("Unable to parse CVSSv3 score from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv3)
		} else {
			cvss3Ptr, err := types.ConvertCVSSv3(vector)
			if err != nil {
				log.Errorf("Unable to parse CVSSv3 vector from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv3)
			} else {
				cvss3 = *cvss3Ptr
				if score != cvss3Ptr.Score {
					log.Warnf("Given CVSSv3 score and computed score differ for RHEL vulnerability %s: %f != %f. Using given score...", vuln.Name, score, cvss3Ptr.Score)
					cvss3Ptr.Score = score
				}
			}
		}
	}

	metadata := map[string]interface{}{
		"Red Hat": &types.Metadata{
			PublishedDateTime:    vuln.Issued.String(),
			LastModifiedDateTime: vuln.Updated.String(),
			CVSSv2:               cvss2,
			CVSSv3:               cvss3,
		},
	}

	return Vulnerability{
		Name:          vuln.Name,
		NamespaceName: namespace, // TODO: Purpose?
		Description:   vuln.Description,
		Link:          vuln.Link,
		Severity:      vuln.Severity,
		Metadata:      metadata,
		FixedBy:       vuln.FixedInVersion, // Empty string if not fixed.
	}
}

///////////////////////////////////////////////////
// END
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

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
	Location        string          `json:"Location,omitempty"`
	FixedBy         string          `json:"FixedBy,omitempty"`
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
	Notes []Note `json:"Notes,omitempty"`
	Error *Error `json:"Error,omitempty"`
}

type Note int

const (
	// OSCVEsUnavailable labels scans of images with unknown namespaces or obsolete namespaces.
	OSCVEsUnavailable Note = iota
	// OSCVEsStale labels scans of images with namespaces whose CVEs are known to be stale.
	OSCVEsStale
	// LanguageCVEsUnavailable labels scans of images with without language CVEs.
	// This is typically only populated when language CVEs are not enabled.
	LanguageCVEsUnavailable
)

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
