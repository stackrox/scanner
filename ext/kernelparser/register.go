package kernelparser

import (
	"fmt"

	"github.com/stackrox/scanner/database"
)

var (
	Parsers = make(map[string]Parser)
)

type ParseMatch struct {
	Namespace   string
	Format      string
	FeatureName string
	Version     string
}

type Parser func(db database.Datastore, kernelVersion, osImage string) (*ParseMatch, bool)

func RegisterParser(name string, parser Parser) {
	if _, ok := Parsers[name]; ok {
		panic(fmt.Sprintf("parser %s is already registered", name))
	}
	Parsers[name] = parser
}
