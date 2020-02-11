package licenses

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	licenseproto "github.com/stackrox/rox/generated/shared/license"
	"github.com/stackrox/rox/pkg/license/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	validLicenseKey = "valid"
)

type mockValidator struct {
	license *licenseproto.License
}

func (m mockValidator) RegisterSigningKey(algo string, raw []byte, restrictions *validator.SigningKeyRestrictions) error {
	panic("Not implemented")
}

func (m mockValidator) ValidateLicenseKey(licenseKey string) (*licenseproto.License, error) {
	if licenseKey == validLicenseKey {
		return m.license, nil
	}
	return nil, errors.New("invalid license")
}

func getLicense(nvb, nva time.Time, t *testing.T) *licenseproto.License {
	nvbProto, err := types.TimestampProto(nvb)
	require.NoError(t, err)

	nvaProto, err := types.TimestampProto(nva)
	require.NoError(t, err)
	return &licenseproto.License{
		Restrictions: &licenseproto.License_Restrictions{
			NotValidBefore: nvbProto,
			NotValidAfter:  nvaProto,
		},
	}
}

func TestValidator(t *testing.T) {
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	anHourAgo := time.Now().Add(-1 * time.Hour)
	anHourLater := time.Now().Add(time.Hour)
	twoHoursLater := time.Now().Add(2 * time.Hour)

	for _, testCase := range []struct {
		description    string
		licenseKey     string
		license        *licenseproto.License
		expectedErr    bool
		expectedExpiry time.Time
	}{
		{
			"valid license",
			validLicenseKey,
			getLicense(anHourAgo, anHourLater, t),
			false,
			anHourLater,
		},
		{
			"invalid license",
			"invalid",
			nil,
			true,
			time.Time{},
		},
		{
			"valid but expired license",
			validLicenseKey,
			getLicense(twoHoursAgo, anHourAgo, t),
			true,
			time.Time{},
		},
		{
			"valid but too early license",
			validLicenseKey,
			getLicense(anHourLater, twoHoursLater, t),
			true,
			time.Time{},
		},
	} {
		c := testCase
		t.Run(c.description, func(t *testing.T) {
			expiry, err := validateWithValidator(c.licenseKey, mockValidator{c.license})
			if c.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.True(t, expiry.Equal(c.expectedExpiry), "Expected: %s, got %s", c.expectedExpiry, c.expectedErr)
			}
		})
	}

}
