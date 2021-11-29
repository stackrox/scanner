package updater

import (
	"time"
)

// Config defines the updater's configuration settings.
// Any updates to this should be tested in cmd/clair/config_test.go.
type Config struct {
	Interval time.Duration `json:"interval"`
}
