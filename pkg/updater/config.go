package updater

import (
	"time"
)

// Config defines the updater's configuration settings.
type Config struct {
	Interval time.Duration `yaml:"interval"`
	// FetchFromCentral represents whether to fetch vulns from Central instead of from stackrox.io.
	// Currently, we don't support fetching from both. It's one or the other depending on whether
	// you're in offline mode or not.
	FetchFromCentral bool `yaml:"fetchFromCentral"`
}
