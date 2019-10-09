package types

type ComponentType int

const (
	JAR ComponentType = iota
)

type Component struct {
	Name        string
	Version     string
	Type        ComponentType
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
