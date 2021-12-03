package updater

import (
	"encoding/json"
	"time"
)

// Config defines the updater's configuration settings.
// Any updates to this should be tested in cmd/clair/config_test.go.
type Config struct {
	Interval time.Duration `json:"interval"`
}

type config struct {
	Interval string `json:"interval"`
}

// UnmarshalJSON is needed to implement json/Unmarshaler.
func (c *Config) UnmarshalJSON(b []byte) error {
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}

	var err error
	c.Interval, err = time.ParseDuration(cfg.Interval)
	return err
}
