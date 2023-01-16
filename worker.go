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
	"github.com/stackrox/scanner/ext/imagefmt"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/analyzer/detection"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/env"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/tarutil"
	"github.com/stackrox/scanner/singletons/analyzers"
	"github.com/stackrox/scanner/singletons/requiredfilenames"
)

const (
	// Version (integer) represents the worker version.
	// Increased each time the engine changes.
	Version = 3
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
				log.WithFields(log.Fields{detection.LogLayerName: name, "parent layer": parentName}).Warning("the parent layer is unknown. it must be processed first")
				return layer, false, detection.ErrParentUnknown
			}
			layer.Parent = &parent
		}
		return layer, false, nil
	}
	// The layer is already in the database, check if we need to update it.
	if layer.EngineVersion >= Version {
		log.WithFields(log.Fields{detection.LogLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. skipping analysis")
		return layer, true, nil
	}
	log.WithFields(log.Fields{detection.LogLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. analyzing again")
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
	// Get the list of language analyzers if language vulnerability is enabled.
	var langAnalyzers []analyzer.Analyzer
	if env.LanguageVulns.Enabled() {
		langAnalyzers = analyzers.Analyzers()
	}
	// Create a "matcher" that actually calls `ProcessFile` on each analyzer, before
	// delegating to the actual matcher for operating system-level feature
	// extraction.
	//
	// TODO: This is ugly. A matcher should not have side-effects; but the `analyzingMatcher`s
	//       sole purpose is to have a side effect. The `ExtractFromReader` should be more
	//       explicit about the matcher not just being a matcher.
	m := &analyzingMatcher{
		analyzers: langAnalyzers,
		delegate:  requiredfilenames.SingletonMatcher(),
	}

	files, err := imagefmt.ExtractFromReader(reader, format, m)
	if err != nil {
		return nil, false, nil, nil, nil, nil, err
	}
	files.MergeBaseAndResolveSymlinks(base)

	if len(m.components) > 0 {
		log.WithFields(log.Fields{detection.LogLayerName: name, "component count": len(m.components)}).Debug("detected components")
	}

	namespace, features, rhelv2Components, languageComponents, err := detection.DetectComponents(name, *files, parent, m.components,
		detection.DetectComponentOpts{UncertifiedRHEL: uncertifiedRHEL, IsRHCOSRequired: false})
	distroless := isDistroless(*files) || (parent != nil && parent.Distroless)

	return namespace, distroless, features, rhelv2Components, languageComponents, files, err
}

func isDistroless(filesMap tarutil.LayerFiles) bool {
	_, ok := filesMap.Get("var/lib/dpkg/status.d/")
	return ok
}
