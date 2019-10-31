package component

// Type represents the specific type of a language-level component.
//go:generate stringer -type=Type
type Type int

// This block enumerates valid types.
const (
	UnsetType Type = iota
	JavaType
	PythonType
)
