// Package features helps enable or disable features.
package features

import (
	"fmt"
	"strings"
)

// A FeatureFlag is a product behavior that can be enabled or disabled using an environment variable.
type FeatureFlag interface {
	Name() string
	EnvVar() string
	Enabled() bool
}

var (
	// Flags contains all defined FeatureFlags by name.
	Flags = make(map[string]FeatureFlag)
)

func registerFeature(name, envVar string, defaultValue bool, opts ...FeatureFlagOption) FeatureFlag {
	if !strings.HasPrefix(envVar, "ROX_") {
		panic(fmt.Sprintf("invalid env var: %s, must start with ROX_", envVar))
	}

	var appliedOpts options
	for _, opt := range opts {
		opt.apply(&appliedOpts)
	}

	f := &feature{
		name:         name,
		envVar:       envVar,
		defaultValue: defaultValue,
		options:      appliedOpts,
	}
	Flags[f.Name()] = f
	return f
}
