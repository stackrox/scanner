package cpe

import (
	"fmt"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	generators = make(map[component.SourceType]Generator)
)

type Generator func(c *component.Component, vendors, packages, versions set.StringSet)

func Register(name component.SourceType, generator Generator) {
	if _, ok := generators[name]; ok {
		panic(fmt.Sprintf("%q has already been registered", name))
	}
	generators[name] = generator
}
