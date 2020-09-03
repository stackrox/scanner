package features

import (
	"os"
	"strings"
)

type feature struct {
	envVar       string
	name         string
	defaultValue bool
	options      options
}

func (f *feature) EnvVar() string {
	return f.envVar
}

func (f *feature) Name() string {
	return f.name
}

func (f *feature) Enabled() bool {
	envVal := os.Getenv(f.envVar)
	if envVal == "" && f.options.noRoxAllowed {
		// Remove ROX_ prefix.
		envVal = os.Getenv(f.envVar[4:])
	}

	switch strings.ToLower(envVal) {
	case "false":
		return false
	case "true":
		return true
	default:
		return f.defaultValue
	}
}
