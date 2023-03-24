package env

import (
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
)

// DurationSetting represents an environment variable which should be parsed into a duration
type DurationSetting struct {
	envVar          string
	defaultDuration time.Duration
	opts            durationSettingOpts
}

// DurationSetting returns the Duration object represented by the environment variable
func (d *DurationSetting) DurationSetting() time.Duration {
	val := os.Getenv(d.envVar)
	if val != "" {
		dur, err := time.ParseDuration(val)
		if err == nil && validateDuration(dur, d.opts) == nil {
			return dur
		}
		log.Warnf("%s is not a valid environment variable for %s, using default value: %v", val, d.envVar, d.defaultDuration)
	}
	return d.defaultDuration
}

func RegisterDurationSetting(envVar string, defaultDuration time.Duration, options ...DurationSettingOption) *DurationSetting {
	var opts durationSettingOpts
	for _, o := range options {
		o.apply(&opts)
	}
	utils.CrashOnError(validateDuration(defaultDuration, opts))

	s := &DurationSetting{
		envVar:          envVar,
		defaultDuration: defaultDuration,
		opts:            opts,
	}

	ValidateSettingName(envVar)
	return s
}

func validateDuration(d time.Duration, opts durationSettingOpts) error {
	if d < 0 {
		return fmt.Errorf("invalid duration: %v < 0", d)
	}
	if !opts.zeroAllowed && d == 0 {
		return fmt.Errorf("invalid duration: %v == 0", d)
	}
	return nil
}
