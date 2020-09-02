package features

import (
	"os"
	"strings"
)

type feature struct {
	envVar       string
	name         string
	defaultValue bool
	noRoxAllowed bool
}

func (f *feature) EnvVar() string {
	return f.envVar
}

func (f *feature) Name() string {
	return f.name
}

func (f *feature) Enabled() bool {
	switch strings.ToLower(os.Getenv(f.envVar)) {
	case "false":
		return false
	case "true":
		return true
	}

	if f.noRoxAllowed {
		// Remove the ROX_ prefix.
		switch strings.ToLower(os.Getenv(f.envVar[4:])) {
		case "false":
			return false
		case "true":
			return true
		}
	}

	return f.defaultValue
}
