package detection

import (
	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurefmt"
	"github.com/stackrox/scanner/ext/featurens"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	features2 "github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/rhelv2/rpm"
	"github.com/stackrox/scanner/pkg/wellknownnamespaces"
)

// LogLayerName is the name of the log field holding the detection target.
const LogLayerName = "layer"

// DetectComponents detects the namespace and extracts the components present in
// the files of a filesystem or image layer. For layers, the parent layer should
// be specified. For filesystems, which don't have the concept of intermediate
// layers, or the root layer, use `nil`. Notice that language components are not
// extracted by DetectComponents, but if provided they are annotated with
// certified RHEL dependencies, and returned.
func DetectComponents(name string, files analyzer.Files, parent *database.Layer, languageComponents []*component.Component, uncertifiedRHEL bool) (*database.Namespace, []database.FeatureVersion, *database.RHELv2Components, []*component.Component, error) {
	namespace := DetectNamespace(name, files, parent, uncertifiedRHEL)

	var featureVersions []database.FeatureVersion
	var rhelFeatures *database.RHELv2Components
	var err error

	// In the current state, RHCOS will always be handled as certified system.
	// If no CPEs are found on RHCOS, a note needs to be added that informs users of it.
	// Also, the bool logic can be refactored into a single UseCertifiedWorkflow function.
	// TODO(ROX-13906, ROX-14028): Implement note and refactor
	if isCertifiedRHELNamespace(namespace) {
		rhelFeatures, languageComponents, err = detectAndAnnotateCertifiedRHELComponents(name, files, namespace, languageComponents)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		logrus.WithFields(logrus.Fields{
			LogLayerName:         name,
			"rhel package count": len(rhelFeatures.Packages),
			"rhel cpe count":     len(rhelFeatures.CPEs),
			"rhel content sets":  len(rhelFeatures.ContentSets),
		}).Debug("detected rhelv2 features")
	} else {
		featureVersions, err = detectFeatureVersions(name, files, namespace, parent)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		logrus.WithFields(logrus.Fields{
			LogLayerName:    name,
			"feature count": len(featureVersions),
		}).Debug("detected features")
	}
	return namespace, featureVersions, rhelFeatures, languageComponents, nil
}

func isCertifiedRHELNamespace(namespace *database.Namespace) bool {
	if namespace == nil {
		return false
	}
	return wellknownnamespaces.IsRHELNamespace(namespace.Name) ||
		wellknownnamespaces.IsRHCOSNamespace(namespace.Name)
}

func detectAndAnnotateCertifiedRHELComponents(name string, files analyzer.Files, namespace *database.Namespace, languageComponents []*component.Component) (*database.RHELv2Components, []*component.Component, error) {
	// This is a certified image that needs to be scanned differently.
	// Use the RHELv2 scanner instead.
	packages, contentSets, err := rpm.ListFeatures(files)
	if err != nil {
		return nil, nil, err
	}
	rhelfeatures := &database.RHELv2Components{
		Dist:     namespace.Name,
		Packages: packages,
		// CPEs are mapped and returned with content sets for backward compatibility.
		CPEs:        repo2cpe.Singleton().Get(contentSets),
		ContentSets: contentSets,
	}
	if err := rpm.AnnotateComponentsWithPackageManagerInfo(files, languageComponents); err != nil {
		logrus.WithError(err).Errorf("Failed to analyze package manager info for language components: %s", name)
	}
	return rhelfeatures, languageComponents, nil
}

// DetectNamespace detects the layer's namespace.
func DetectNamespace(name string, files analyzer.Files, parent *database.Layer, uncertifiedRHEL bool) *database.Namespace {
	namespace := featurens.Detect(files, &featurens.DetectorOptions{
		UncertifiedRHEL: uncertifiedRHEL,
	})
	if namespace != nil {
		logrus.WithFields(logrus.Fields{LogLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace")
		return namespace
	}

	// Fallback to the parent's namespace.
	if parent != nil {
		namespace = parent.Namespace
		if namespace != nil {
			logrus.WithFields(logrus.Fields{LogLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace (from parent)")
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

		logrus.WithFields(logrus.Fields{"feature name": feature.Feature.Name, "feature version": feature.Version, LogLayerName: name}).Warning("Namespace unknown")
		if features2.ContinueUnknownOS.Enabled() {
			features = nil
			return
		}

		err = ErrUnsupported
		return
	}

	return
}
