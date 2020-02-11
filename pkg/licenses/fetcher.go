package licenses

import (
	"errors"
)

var (
	ErrNoValidLicense = errors.New("no valid license")
)

type StatusProvider interface {
	LicenseValid() bool
}
