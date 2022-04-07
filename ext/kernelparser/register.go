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
// Returns a non-nil *ParseMatch, match, if the OS/Kernel is supported.
// If an OS is explicitly unsupported, match is nil, ok is true, and err is nil.
// This indicates the Parser knows how to handle this OS but does not support it.
type Parser func(db database.Datastore, kernelVersion, osImage string) (match *ParseMatch, ok bool, err error)

// RegisterParser registers the given kernel parser.
func RegisterParser(name string, parser Parser) {
	if _, ok := Parsers[name]; ok {
		panic(fmt.Sprintf("parser %s is already registered", name))
	}
	Parsers[name] = parser
}
