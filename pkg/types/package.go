package types

type Component struct {
	Name        string
	Version     string
	JavaPackage *JavaPackage
}

type JavaPackage struct {
	ImplementationVersion string
	Location              string
	MavenVersion          string
	Name                  string
	Origin                string
	SpecificationVersion  string
}
