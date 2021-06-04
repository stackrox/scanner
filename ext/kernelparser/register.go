package kernelparser

import (
	"fmt"

	"github.com/stackrox/scanner/database"
)

var (
	// Parsers contains all the registered kernel parsers.
	Parsers = make(map[string]Parser)
)

// ParseMatch is the return value for the Parser function.
type ParseMatch struct {
	Namespace   string
	Format      string
	FeatureName string
	Version     string
}

// Parser is a kernel parser.
type Parser func(db database.Datastore, kernelVersion, osImage string) (*ParseMatch, bool, error)

// RegisterParser registers the given kernel parser.
func RegisterParser(name string, parser Parser) {
	if _, ok := Parsers[name]; ok {
		panic(fmt.Sprintf("parser %s is already registered", name))
	}
	Parsers[name] = parser
}
