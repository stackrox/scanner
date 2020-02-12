package licenses

import (
	"github.com/pkg/errors"
)

var (
	// ErrNoValidLicense is the error returned by scanner APIs when scanner hasn't detected a valid license yet.
	ErrNoValidLicense = errors.New("no valid license")
)
