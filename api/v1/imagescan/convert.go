package imagescan

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/database"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	errSourceTypesMismatch = errors.New("Number of source types in proto and Go are not equal")
	errNotesMismatch       = errors.New("Number of notes in proto and Go are not equal")

	sourceTypeToProtoMap = func() map[component.SourceType]v1.SourceType {
		numComponentSourceTypes := int(component.SentinelEndSourceType) - int(component.UnsetSourceType)
		if numComponentSourceTypes != len(v1.SourceType_value) {
			utils.CrashOnError(errSourceTypesMismatch)
		}

		m := make(map[component.SourceType]v1.SourceType, numComponentSourceTypes)
		for name, val := range v1.SourceType_value {
			normalizedName := strings.ToLower(strings.TrimSuffix(name, "_SOURCE_TYPE"))
			for sourceType := component.UnsetSourceType; sourceType < component.SentinelEndSourceType; sourceType++ {
				if strings.HasPrefix(strings.ToLower(sourceType.String()), normalizedName) {
					m[sourceType] = v1.SourceType(val)
				}
			}
		}
		if len(m) != numComponentSourceTypes {
			utils.CrashOnError(errSourceTypesMismatch)
		}
		return m
	}()

	noteToProtoMap = func() map[apiV1.Note]v1.Note {
		numNotes := int(apiV1.SentinelNote)
		if numNotes != len(v1.Note_value) {
			utils.CrashOnError(errNotesMismatch)
		}

		m := make(map[apiV1.Note]v1.Note, numNotes)
		for name, val := range v1.Note_value {
			normalizedName := strings.ToLower(strings.Replace(name, "_", "", -1))
			for note := apiV1.OSCVEsUnavailable; note < apiV1.SentinelNote; note++ {
				if strings.HasPrefix(strings.ToLower(note.String()), normalizedName) {
					m[note] = v1.Note(val)
				}
			}
		}
		if len(m) != numNotes {
			utils.CrashOnError(errNotesMismatch)
		}
		return m
	}()
)

func convertVulnerabilities(apiVulns []apiV1.Vulnerability) []*v1.Vulnerability {
	vulns := make([]*v1.Vulnerability, 0, len(apiVulns))
	for _, v := range apiVulns {
		metadata, err := convert.MetadataMap(v.Metadata)
		if err != nil {
			log.Errorf("error converting metadata map: %v", err)
			continue
		}
		if metadata == nil {
			log.Warnf("metadata is nil for %s; skipping...", v.Name)
			continue
		}

		vulns = append(vulns, &v1.Vulnerability{
			Name:        v.Name,
			Description: v.Description,
			Link:        v.Link,
			MetadataV2:  metadata,
			FixedBy:     v.FixedBy,
		})
	}
	return vulns
}

func convertProvidedExecutables(paths []string) []*v1.Executable {
	executables := make([]*v1.Executable, 0, len(paths))
	for _, path := range paths {
		executables = append(executables, &v1.Executable{
			Path: path,
		})
	}

	return executables
}

// ConvertExecutables converts executables into the paths.
func ConvertExecutables(executables []*v1.Executable) []string {
	paths := make([]string, 0, len(executables))
	for _, executable := range executables {
		paths = append(paths, executable.Path)
	}

	return paths
}

// ConvertFeatures converts api Features into v1 (proto) Feature pointers.
func ConvertFeatures(apiFeatures []apiV1.Feature) []*v1.Feature {
	features := make([]*v1.Feature, 0, len(apiFeatures))
	for _, a := range apiFeatures {
		vulns := convertVulnerabilities(a.Vulnerabilities)
		executables := convertProvidedExecutables(a.ProvidedExecutables)

		features = append(features, &v1.Feature{
			Name:                a.Name,
			Version:             a.Version,
			Vulnerabilities:     vulns,
			FeatureType:         a.VersionFormat,
			AddedByLayer:        a.AddedBy,
			Location:            a.Location,
			ProvidedExecutables: executables,
		})
	}
	return features
}

func convertLanguageLevelComponents(layersToComponents []*component.LayerToComponents) map[string]*v1.LanguageLevelComponents {
	converted := make(map[string]*v1.LanguageLevelComponents, len(layersToComponents))
	for _, layerToComponents := range layersToComponents {
		converted[layerToComponents.Layer] = convertLanguageLevelComponentsSlice(layerToComponents.Components)
	}
	return converted
}

func convertLanguageLevelComponentsSlice(components []*component.Component) *v1.LanguageLevelComponents {
	converted := make([]*v1.LanguageLevelComponent, 0, len(components))
	for _, c := range components {
		converted = append(converted, convertLanguageLevelComponent(c))
	}
	return &v1.LanguageLevelComponents{
		Components: converted,
	}
}

func convertLanguageLevelComponent(c *component.Component) *v1.LanguageLevelComponent {
	return &v1.LanguageLevelComponent{
		SourceType: sourceTypeToProtoMap[c.SourceType],
		Name:       c.Name,
		Version:    c.Version,
		Location:   c.Location,
	}
}

func convertNotes(notes []apiV1.Note) []v1.Note {
	v1Notes := make([]v1.Note, 0, len(notes))
	for _, note := range notes {
		v1Notes = append(v1Notes, noteToProtoMap[note])
	}
	return v1Notes
}

// convertFeaturesAndComponents converts the given OS-level features and language-level components into
// Components.
func convertFeaturesAndComponents(features []apiV1.Feature, rhelv2PkgEnvs map[int]*database.RHELv2PackageEnv, components []*component.Component) *v1.Components {
	osComponents := make([]*v1.OSComponent, 0, len(features))
	for _, feature := range features {
		osComponents = append(osComponents, &v1.OSComponent{
			Name:        feature.Name,
			Namespace:   feature.NamespaceName,
			Version:     feature.Version,
			AddedBy:     feature.AddedBy,
			Executables: convertProvidedExecutables(feature.ProvidedExecutables),
		})
	}

	rhelv2Components := make([]*v1.RHELComponent, 0, len(rhelv2PkgEnvs))
	for _, rhelv2PkgEnv := range rhelv2PkgEnvs {
		pkg := rhelv2PkgEnv.Pkg
		rhelv2Components = append(rhelv2Components, &v1.RHELComponent{
			Id:          strconv.Itoa(pkg.ID),
			Name:        pkg.Name,
			Namespace:   rhelv2PkgEnv.Namespace,
			Version:     pkg.Version,
			Arch:        pkg.Arch,
			Module:      pkg.Module,
			Cpes:        rhelv2PkgEnv.CPEs,
			AddedBy:     rhelv2PkgEnv.AddedBy,
			Executables: convertProvidedExecutables(pkg.ProvidedExecutables),
		})
	}

	languageComponents := make([]*v1.LanguageComponent, 0, len(components))
	for _, c := range components {
		languageComponent := &v1.LanguageComponent{
			Type:     sourceTypeToProtoMap[c.SourceType],
			Name:     c.Name,
			Version:  c.Version,
			Location: c.Location,
			AddedBy:  c.AddedBy,
		}

		switch c.SourceType {
		case component.JavaSourceType:
			javaMetadata := c.JavaPkgMetadata
			if javaMetadata == nil {
				log.Warn("TODO")
			} else {
				languageComponent.Language = &v1.LanguageComponent_Java{
					Java: &v1.JavaComponent{
						ImplementationVersion: javaMetadata.ImplementationVersion,
						MavenVersion:          javaMetadata.MavenVersion,
						Origins:               javaMetadata.Origins,
						SpecificationVersion:  javaMetadata.SpecificationVersion,
						BundleName:            javaMetadata.BundleName,
					},
				}
			}
		case component.PythonSourceType:
			pythonMetadata := c.PythonPkgMetadata
			if pythonMetadata == nil {
				log.Warn("TODO")
			} else {
				languageComponent.Language = &v1.LanguageComponent_Python{
					Python: &v1.PythonComponent{
						Homepage:    pythonMetadata.Homepage,
						AuthorEmail: pythonMetadata.AuthorEmail,
						DownloadUrl: pythonMetadata.DownloadURL,
						Summary:     pythonMetadata.Summary,
						Description: pythonMetadata.Description,
					},
				}
			}
		}

		languageComponents = append(languageComponents, languageComponent)
	}

	return &v1.Components{
		OsComponents:       osComponents,
		RhelComponents:     rhelv2Components,
		LanguageComponents: languageComponents,
	}
}
