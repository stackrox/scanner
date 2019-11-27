package component

// A Component represents a software component that is installed in an image.
type Component struct {
	// Analyzers MUST ensure that the name, version and source type are set in every component
	// they return, since a component is not meaningful without those fields.
	// All other fields are optional.

	Name    string
	Version string

	SourceType SourceType

	// Location specifies a path to a file that the component's existence was derived from.
	Location string

	JavaPkgMetadata *JavaPkgMetadata
}

// LayerToComponents describes a layer to the components found in the layer
type LayerToComponents struct {
	Layer      string
	Components []*Component
}

// JavaPkgMetadata contains additional metadata that Java-based components have.
type JavaPkgMetadata struct {
	ImplementationVersion string
	MavenVersion          string
	Origin                string
	SpecificationVersion  string
}
