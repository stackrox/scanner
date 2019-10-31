package component

// A Component represents a software component that is installed in an image.
type Component struct {
	Name    string
	Version string

	SourceType SourceType

	// Location specifies a path to a file that the component's existence was derived from.
	Location string

	JavaPkgMetadata *JavaPkgMetadata
}

// JavaPkgMetadata contains additional metadata that Java-based components have.
type JavaPkgMetadata struct {
	ImplementationVersion string
	MavenVersion          string
	Name                  string
	Origin                string
	SpecificationVersion  string
}
