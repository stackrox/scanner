package env

import (
	"strconv"
)

// IntegerSetting represents an environment variable which should be parsed into an integer.
type IntegerSetting interface {
	Setting
	Int() int
}

type integerSetting struct {
	Setting
	defaultValue int
}

// Int returns the int object represented by the environment variable.
func (s *integerSetting) Int() int {
	v, err := strconv.Atoi(s.Value())
	if err != nil {
		return s.defaultValue
	}
	return v
}

// RegisterIntegerSetting globally registers and returns a new integer setting.
func RegisterIntegerSetting(envVar string, defaultValue int, opts ...SettingOption) IntegerSetting {
	return &integerSetting{
		Setting:      registerSetting(envVar, append(opts, WithDefault(strconv.Itoa(defaultValue)))...),
		defaultValue: defaultValue,
	}
}
