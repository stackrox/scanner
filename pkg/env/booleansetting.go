package env

import (
	"strconv"
)

type BooleanSetting interface {
	Setting
	Enabled() bool
}

// booleanSetting represents an environment variable which should be parsed into a boolean
type booleanSetting struct {
	Setting
}

// Enabled returns the bool object represented by the environment variable
func (s *booleanSetting) Enabled() bool {
	v, err := strconv.ParseBool(s.Setting.Setting())
	return v && err == nil
}

// registerBooleanSetting globally registers and returns a new boolean setting.
func registerBooleanSetting(envVar string, defaul bool, opts ...SettingOption) BooleanSetting {
	return &booleanSetting{
		Setting: registerSetting(envVar, append(opts, WithDefault(strconv.FormatBool(defaul)))...),
	}
}
