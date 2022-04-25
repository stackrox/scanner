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
// osImage is expected to be lowercase (for example by calling `strings.ToLower(osImage)`).
// Returns a non-nil *ParseMatch if the kernel is supported.
type Parser func(db database.Datastore, kernelVersion, osImage string) (*ParseMatch, error)

// RegisterParser registers the given kernel parser.
func RegisterParser(name string, parser Parser) {
	if _, ok := Parsers[name]; ok {
		panic(fmt.Sprintf("parser %s is already registered", name))
	}
	Parsers[name] = parser
}
