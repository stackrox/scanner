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
// Returns a non-nil *ParseMatch, match, if the kernel is supported.
// Returns ok = true if the kernel was recognized by the parser.
// Returns a non-nil error when there is an error parsing the kernel or if the node represented by the
// osImage and kernel is recognized and completely unsupported.
type Parser func(db database.Datastore, kernelVersion, osImage string) (match *ParseMatch, ok bool, err error)

// RegisterParser registers the given kernel parser.
func RegisterParser(name string, parser Parser) {
	if _, ok := Parsers[name]; ok {
		panic(fmt.Sprintf("parser %s is already registered", name))
	}
	Parsers[name] = parser
}
