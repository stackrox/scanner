package rhel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPull(t *testing.T) {
	up := updater{}
	resp, err := up.Update(nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
