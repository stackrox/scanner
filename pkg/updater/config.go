package updater

import (
	"time"
)

type Config struct {
	Interval time.Duration `yaml:"interval"`
}
