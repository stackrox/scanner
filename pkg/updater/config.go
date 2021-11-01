package updater

import (
	"time"
)

// Config defines the updater's configuration settings.
type Config struct {
	Interval time.Duration `yaml:"interval"`
}
