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

package clair

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	featureFlags "github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/matcher"
	rhelv2 "github.com/stackrox/scanner/pkg/rhelv2/rpm"
	"github.com/stackrox/scanner/pkg/tarutil"
	namespaces "github.com/stackrox/scanner/pkg/wellknownnamespaces"
	"github.com/stackrox/scanner/singletons/analyzers"
	"github.com/stackrox/scanner/singletons/requiredfilenames"
)

const (
	// Version (integer) represents the worker version.
	// Increased each time the engine changes.
	Version      = 3
	logLayerName = "layer"
)

var (
	// ErrUnsupported is the error that should be raised when an OS or package
	// manager is not supported.
	ErrUnsupported = commonerr.NewBadRequestError("worker: OS and/or package manager are not supported")

	// ErrParentUnknown is the error that should be raised when a parent layer
	// has yet to be processed for the current layer.
	ErrParentUnknown = commonerr.NewBadRequestError("worker: parent layer is unknown, it must be processed first")
)

func preProcessLayer(datastore database.Datastore, imageFormat, name, lineage, parentName, parentLineage string, uncertifiedRHEL bool) (database.Layer, bool, error) {
	// Verify parameters.
	if name == "" {
		return database.Layer{}, false, commonerr.NewBadRequestError("could not process a layer which does not have a name")
	}

	if imageFormat == "" {
		return database.Layer{}, false, commonerr.NewBadRequestError("could not process a layer which does not have a format")
	}

	// Check to see if the layer is already in the database.
	layer, err := datastore.FindLayer(name, lineage, &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if err != nil && err != commonerr.ErrNotFound {
		return layer, false, err
	}

	if err == commonerr.ErrNotFound {
		// New layer case.
		layer = database.Layer{Name: name, EngineVersion: Version}

		// Retrieve the parent if it has one.
		// We need to get it with its Features in order to diff them.
		if parentName != "" {
			// rolling hash of parents up to point
			parent, err := datastore.FindLayer(parentName, parentLineage, &database.DatastoreOptions{
				WithFeatures:    true,
				UncertifiedRHEL: uncertifiedRHEL,
			})
			if err != nil && err != commonerr.ErrNotFound {
				return layer, false, err
			}
			if err == commonerr.ErrNotFound {
				log.WithFields(log.Fields{logLayerName: name, "parent layer": parentName}).Warning("the parent layer is unknown. it must be processed first")
				return layer, false, ErrParentUnknown
			}
			layer.Parent = &parent
		}
		return layer, false, nil
	}
	// The layer is already in the database, check if we need to update it.
	if layer.EngineVersion >= Version {
		log.WithFields(log.Fields{logLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. skipping analysis")
		return layer, true, nil
	}
	log.WithFields(log.Fields{logLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. analyzing again")
	return layer, false, nil
}

// ProcessLayerFromReader detects the Namespace of a layer, the features it adds/removes,
// and then stores everything in the database.
//
// TODO(Quentin-M): We could have a goroutine that looks for layers that have
// been analyzed with an older engine version and that processes them.
func ProcessLayerFromReader(datastore database.Datastore, imageFormat, name, lineage, parentName, parentLineage string, reader io.ReadCloser, base *tarutil.LayerFiles, uncertifiedRHEL bool) (*tarutil.LayerFiles, error) {
	// Ensure the reader is closed. This *should* happen on all paths, but better safe
	// than sorry.
	defer utils.IgnoreError(reader.Close)

	layer, exists, err := preProcessLayer(datastore, imageFormat, name, lineage, parentName, parentLineage, uncertifiedRHEL)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, nil
	}

	// Analyze the content.
	var rhelv2Components *database.RHELv2Components
	var languageComponents []*component.Component
	var files *tarutil.LayerFiles
	layer.Namespace, layer.Distroless, layer.Features, rhelv2Components, languageComponents, files, err = DetectContentFromReader(reader, imageFormat, name, layer.Parent, base, uncertifiedRHEL)
	if err != nil {
		return nil, err
	}

	if rhelv2Components != nil {
		// Go this path for Red Hat Certified scans.
		var parentHash string
		if layer.Parent != nil && layer.Parent.Name != "" {
			parentHash = layer.Parent.Name
		}
		rhelv2Layer := &database.RHELv2Layer{
			Hash:       layer.Name,
			Dist:       rhelv2Components.Dist,
			Pkgs:       rhelv2Components.Packages,
			CPEs:       rhelv2Components.CPEs,
			ParentHash: parentHash,
		}

		if err := datastore.InsertRHELv2Layer(rhelv2Layer); err != nil {
			return nil, err
		}
	}

	opts := &database.DatastoreOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	}

	// This is required for RHEL-base images as well, as language vuln scanning
	// relies on the original layer table.
	if err := datastore.InsertLayer(layer, lineage, opts); err != nil {
		if err == commonerr.ErrNoNeedToInsert {
			return nil, nil
		}
		return nil, err
	}

	return files, datastore.InsertLayerComponents(layer.Name, lineage, languageComponents, files.GetRemovedFiles(), opts)
}

// DetectFromFiles detects the namespace and extracts the components present in
// the files of a filesystem or image layer. For layers, the parent layer should
// be specified. For filesystems, which don't have the concept of intermediate
// layers, or the root layer, use `nil`. Notice that language components are not
// extracted by DetectFromFiles, but if provided they are annotated with
// certified RHEL dependencies, and returned.
func DetectFromFiles(files analyzer.Files, name string, parent *database.Layer, languageComponents []*component.Component, uncertifiedRHEL bool) (*database.Namespace,
	[]database.FeatureVersion, *database.RHELv2Components, []*component.Component, error) {
	namespace := DetectNamespace(name, files, parent, uncertifiedRHEL)

	var featureVersions []database.FeatureVersion
	var rhelfeatures *database.RHELv2Components

	if namespace != nil && namespaces.IsRHELNamespace(namespace.Name) {
		// This is a RHEL-based image that must be scanned in a certified manner.
		// Use the RHELv2 scanner instead.
		packages, cpes, err := rhelv2.ListFeatures(files)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rhelfeatures = &database.RHELv2Components{
			Dist:     namespace.Name,
			Packages: packages,
			CPEs:     cpes,
		}
		log.WithFields(log.Fields{logLayerName: name, "rhel package count": len(packages), "rhel cpe count": len(cpes)}).Debug("detected rhelv2 features")
		if err := rhelv2.AnnotateComponentsWithPackageManagerInfo(files, languageComponents); err != nil {
			log.WithError(err).Errorf("Failed to analyze package manager info for language components: %s", name)
		}
	} else {
		var err error
		// Detect features.
		featureVersions, err = detectFeatureVersions(name, files, namespace, parent)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if len(featureVersions) > 0 {
			log.WithFields(log.Fields{logLayerName: name, "feature count": len(featureVersions)}).Debug("detected features")
		}
	}
	return namespace, featureVersions, rhelfeatures, languageComponents, nil
}

// analyzingMatcher is a Matcher implementation that calls ProcessFile on each analyzer,
// stores the resulting components, and then delegates to another matcher.
type analyzingMatcher struct {
	analyzers []analyzer.Analyzer
	delegate  matcher.Matcher

	components []*component.Component
}

func (m *analyzingMatcher) Match(filePath string, fi os.FileInfo, contents io.ReaderAt) (bool, bool) {
	for _, a := range m.analyzers {
		m.components = append(m.components, component.FilterToOnlyValid(a.ProcessFile(filePath, fi, contents))...)
	}
	return m.delegate.Match(filePath, fi, contents)
}

// DetectContentFromReader detects scanning content in the given reader.
func DetectContentFromReader(reader io.ReadCloser, format, name string, parent *database.Layer, base *tarutil.LayerFiles, uncertifiedRHEL bool) (*database.Namespace, bool, []database.FeatureVersion, *database.RHELv2Components, []*component.Component, *tarutil.LayerFiles, error) {
	// Create a "matcher" that actually calls `ProcessFile` on each analyzer, before delegating
	// to the actual matcher for operating system-level feature extraction.
	// TODO: this is ugly. A matcher should not have side-effects; but the `analyzingMatcher`s
	// sole purpose is to have a side effect. The `ExtractFromReader` should be more explicit
	// about the matcher not just being a matcher.
	m := &analyzingMatcher{
		analyzers: analyzers.Analyzers(),
		delegate:  requiredfilenames.SingletonMatcher(),
	}

	files, err := imagefmt.ExtractFromReader(reader, format, m)
	if err != nil {
		return nil, false, nil, nil, nil, nil, err
	}
	files.MergeBaseAndResolveSymlinks(base)

	if len(m.components) > 0 {
		log.WithFields(log.Fields{logLayerName: name, "component count": len(m.components)}).Debug("detected components")
	}

	namespace, features, rhelv2Components, languageComponents, err := DetectFromFiles(*files, name, parent, m.components, uncertifiedRHEL)
	distroless := isDistroless(*files) || (parent != nil && parent.Distroless)
	if !env.LanguageVulns.Enabled() {
		languageComponents = nil
	}
	return namespace, distroless, features, rhelv2Components, languageComponents, files, err
}

func isDistroless(filesMap tarutil.LayerFiles) bool {
	_, ok := filesMap.Get("var/lib/dpkg/status.d/")
	return ok
}

// DetectNamespace detects the layer's namespace.
func DetectNamespace(name string, files analyzer.Files, parent *database.Layer, uncertifiedRHEL bool) *database.Namespace {
	namespace := featurens.Detect(files, &featurens.DetectorOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if namespace != nil {
		log.WithFields(log.Fields{logLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace")
		return namespace
	}

	// Fallback to the parent's namespace.
	if parent != nil {
		namespace = parent.Namespace
		if namespace != nil {
			log.WithFields(log.Fields{logLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace (from parent)")
			return namespace
		}
	}

	return nil
}

func detectFeatureVersions(name string, files analyzer.Files, namespace *database.Namespace, parent *database.Layer) (features []database.FeatureVersion, err error) {
	// TODO(Quentin-M): We need to pass the parent image to DetectFeatures because it's possible that
	// some detectors would need it in order to produce the entire feature list (if they can only
	// detect a diff). Also, we should probably pass the detected namespace so detectors could
	// make their own decision.
	features, err = featurefmt.ListFeatures(files)
	if err != nil {
		return
	}

	// If there are no FeatureVersions, use parent's FeatureVersions if possible.
	// TODO(Quentin-M): We eventually want to give the choice to each detectors to use none/some of
	// their parent's FeatureVersions. It would be useful for detectors that can't find their entire
	// result using one Layer.
	if len(features) == 0 && parent != nil {
		features = parent.Features
		return
	}

	// Build a map of the namespaces for each FeatureVersion in our parent layer.
	parentFeatureNamespaces := make(map[string]database.Namespace)
	if parent != nil {
		for _, parentFeature := range parent.Features {
			parentFeatureNamespaces[parentFeature.Feature.Name+":"+parentFeature.Version] = parentFeature.Feature.Namespace
		}
	}

	// Ensure that each FeatureVersion has an associated Namespace.
	for i, feature := range features {
		if feature.Feature.Namespace.Name != "" {
			// There is a Namespace associated.
			continue
		}

		if parentFeatureNamespace, ok := parentFeatureNamespaces[feature.Feature.Name+":"+feature.Version]; ok {
			// The FeatureVersion is present in the parent layer; associate with their Namespace.
			features[i].Feature.Namespace = parentFeatureNamespace
			continue
		}

		if namespace != nil {
			// The Namespace has been detected in this layer; associate it.
			features[i].Feature.Namespace = *namespace
			continue
		}

		log.WithFields(log.Fields{"feature name": feature.Feature.Name, "feature version": feature.Version, logLayerName: name}).Warning("Namespace unknown")
		if featureFlags.ContinueUnknownOS.Enabled() {
			features = nil
			return
		}

		err = ErrUnsupported
		return
	}

	return
}
