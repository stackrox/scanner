package component

// A Component represents a software component that is installed in an image.
type Component struct {
	Name    string
	Version string

	JavaPkgMetadata *JavaPkgMetadata
}

// JavaPkgMetadata contains additional metadata that Java-based components have.
type JavaPkgMetadata struct {
	ImplementationVersion string
	Location              string
	MavenVersion          string
	Name                  string
	Origin                string
	SpecificationVersion  string
}
