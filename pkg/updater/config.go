package updater

import (
	"time"
)

type Config struct {
	Interval time.Duration `yaml:"interval"`
	// FetchFromCentral represents whether to fetch vulns from Central instead of from stackrox.io.
	// Currently, we don't support fetching from both. It's one or the other depending on whether
	// you're in offline mode or not.
	FetchFromCentral bool `yaml:"fetchFromCentral"`
	// CentralEndpoint is the endpoint that central can be reached at. Defaults to central.stackrox if not present in the config.
	CentralEndpoint string `yaml:"centralEndpoint"`
}
