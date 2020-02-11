package licenses

import (
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/license/publickeys"
	"github.com/stackrox/rox/pkg/license/validator"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	knownKeys = []publickeys.KeyAndAlgo{
		publickeys.CI,
		publickeys.Dev,
		publickeys.DevOld,
		publickeys.Demos,
		publickeys.Prod,
		publickeys.QA,
	}

	validatorInstance = func() validator.Validator {
		v := validator.New()
		for _, keyAndAlgo := range knownKeys {
			// Register all the signing keys known to rox, with nil restrictions -- scanner only
			// verifies the signature.
			utils.Must(v.RegisterSigningKey(keyAndAlgo.Algo, keyAndAlgo.Key, nil))
		}
		return v
	}()
)

// Validate validates a license key, checking that the signature is valid,
// and that the license is valid at time.Now().
// If it is valid, it returns a nil error, and the expiration time of the
// license.
func Validate(licenseKey string) (expiry time.Time, err error) {
	return validateWithValidator(licenseKey, validatorInstance)
}

func validateWithValidator(licenseKey string, v validator.Validator) (time.Time, error) {
	licenseProto, err := v.ValidateLicenseKey(licenseKey)
	if err != nil {
		return time.Time{}, err
	}
	notValidBefore, err := types.TimestampFromProto(licenseProto.GetRestrictions().GetNotValidBefore())
	if err != nil {
		return time.Time{}, errors.Wrap(err, "converting not valid before timestamp")
	}

	now := time.Now()
	if now.Before(notValidBefore) {
		return time.Time{}, errors.Errorf("license is not valid before: %s, but now it is %s", notValidBefore, now)
	}

	expiry, err := types.TimestampFromProto(licenseProto.GetRestrictions().GetNotValidAfter())
	if err != nil {
		return time.Time{}, errors.Wrap(err, "converting not valid after timestamp")
	}

	if now.After(expiry) {
		return time.Time{}, errors.Errorf("license expired at %s, but now it is %s", expiry, now)
	}

	return expiry, nil
}
