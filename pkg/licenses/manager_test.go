package licenses

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {
	a := assert.New(t)

	var failedPollsSoFar int
	var shortExpiry time.Time
	var shortExpiryReturned concurrency.Flag
	var returnLongExpiry concurrency.Flag
	var returnedLongExpiry concurrency.Flag

	const numPolls = 5
	const intervalBetweenPolls = 20 * time.Millisecond
	const gracePeriod = 500 * time.Millisecond

	licenseValidateFunc := func(_ concurrency.Waitable, _ string, _ *http.Client) (time.Time, error) {
		if failedPollsSoFar < numPolls {
			failedPollsSoFar++
			return time.Time{}, errors.New("FAIL")
		}
		if !shortExpiryReturned.Get() {
			shortExpiry = time.Now().Add(time.Second)
			shortExpiryReturned.Set(true)
			return shortExpiry, nil

		}
		if returnLongExpiry.Get() {
			a.False(returnedLongExpiry.Get(), "we shouldn't have to return long expiry more than once!")
			returnedLongExpiry.Set(true)
			return time.Now().Add(time.Hour), nil
		}

		// Make sure the polling doesn't start again until we hit expiry!
		a.True(shortExpiry.Before(time.Now()))
		return shortExpiry, nil
	}

	m, err := newManager(concurrency.Never(), "", licenseValidateFunc, nil,
		timeoutProvider{intervalBetweenPolls: intervalBetweenPolls, expiryGracePeriod: gracePeriod})
	require.NoError(t, err)

	a.False(m.ValidLicenseExists())

	// It should poll enough times to get the short expiry.
	a.True(concurrency.PollWithTimeout(shortExpiryReturned.Get, 10*time.Millisecond, 400*time.Millisecond))

	// Now, we should have a valid license.
	a.True(concurrency.PollWithTimeout(m.ValidLicenseExists, 10*time.Millisecond, 100*time.Millisecond))

	// Sleep until the short expiry, and then make sure we still have a valid license.
	time.Sleep(time.Until(shortExpiry))
	a.True(m.ValidLicenseExists())

	// Make sure the license is valid even as we get closer to the grace period.
	time.Sleep(gracePeriod / 2)
	a.True(m.ValidLicenseExists())

	// Make sure that soon after the grace period, the license stops being valid.
	time.Sleep(gracePeriod / 2)
	a.True(concurrency.PollWithTimeout(func() bool {
		return !m.ValidLicenseExists()
	}, 10*time.Millisecond, 100*time.Millisecond))

	// Now, simulate us getting a new license with a long-expiry.
	returnLongExpiry.Set(true)
	a.True(concurrency.PollWithTimeout(m.ValidLicenseExists, 10*time.Millisecond, 100*time.Millisecond))

}
