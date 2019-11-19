// +build integration

package nvd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPull(t *testing.T) {
	a := appender{}
	err := a.BuildCache()
	require.NoError(t, err)
}
