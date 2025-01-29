package imagescan

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	apiV1 "github.com/stackrox/scanner/api/v1"
	"github.com/stackrox/scanner/api/v1/common"
	"github.com/stackrox/scanner/api/v1/convert"
	"github.com/stackrox/scanner/ext/featurefmt"
	v1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	errNotesMismatch = errors.New("Number of notes in proto and Go are not equal")

	noteToProtoMap = func() map[apiV1.Note]v1.Note {
		numNotes := int(apiV1.SentinelNote)
		if numNotes != len(v1.Note_value) {
			utils.CrashOnError(errNotesMismatch)
		}

		m := make(map[apiV1.Note]v1.Note, numNotes)
		for name, val := range v1.Note_value {
			normalizedName := strings.ToLower(strings.ReplaceAll(name, "_", ""))
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
		SourceType: convert.SourceTypeToProtoMap[c.SourceType],
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

// convertImageComponents converts the given OS-level features and language-level components into
// Components.
func convertImageComponents(imgComponents *apiV1.ComponentsEnvelope) *v1.Components {
	osComponents := make([]*v1.OSComponent, 0, len(imgComponents.Features))
	for _, feature := range imgComponents.Features {
		osComponents = append(osComponents, &v1.OSComponent{
			Name:        feature.Name,
			Namespace:   feature.NamespaceName,
			Version:     feature.Version,
			AddedBy:     feature.AddedBy,
			Executables: feature.Executables,
		})
	}

	depMap := common.GetDepMapRHEL(imgComponents.RHELv2PkgEnvs)
	rhelv2Components := make([]*v1.RHELComponent, 0, len(imgComponents.RHELv2PkgEnvs))
	for _, rhelv2PkgEnv := range imgComponents.RHELv2PkgEnvs {
		pkg := rhelv2PkgEnv.Pkg
		pkgKey := featurefmt.PackageKey{Name: pkg.Name, Version: pkg.GetPackageVersion()}
		rhelv2Components = append(rhelv2Components, &v1.RHELComponent{
			Id:          int64(pkg.ID),
			Name:        pkg.Name,
			Namespace:   rhelv2PkgEnv.Namespace,
			Version:     pkg.Version,
			Arch:        pkg.Arch,
			Module:      pkg.Module,
			Cpes:        rhelv2PkgEnv.CPEs,
			AddedBy:     rhelv2PkgEnv.AddedBy,
			Executables: common.CreateExecutablesFromDependencies(pkgKey, pkg.ExecutableToDependencies, depMap),
		})
	}

	languageComponents := convert.LanguageComponents(imgComponents.LanguageComponents)

	return &v1.Components{
		Namespace:          imgComponents.Namespace,
		OsComponents:       osComponents,
		RhelComponents:     rhelv2Components,
		LanguageComponents: languageComponents,
	}
}
