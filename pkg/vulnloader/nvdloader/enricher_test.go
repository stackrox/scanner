package nvdloader

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	// Skip this test in short mode or CI as it requires network access
	if testing.Short() {
		t.Skip("Skipping test that requires network access and git clone")
	}

	// Test fetching .NET vulnerabilities
	result, err := Fetch()
	require.NoError(t, err, "Fetch should succeed")
	require.NotNil(t, result, "result should not be nil")

	// Verify we got some vulnerabilities
	assert.NotEmpty(t, result, "result should contain vulnerabilities")

	// Verify structure of returned data
	for id, wrapper := range result {
		assert.NotEmpty(t, id, "vulnerability ID should not be empty")
		assert.NotNil(t, wrapper, "wrapper should not be nil")

		// Verify LastUpdated timestamp is set
		assert.NotEmpty(t, wrapper.LastUpdated, "LastUpdated should be set")

		// Verify FileFormat fields
		assert.NotEmpty(t, wrapper.ID, "ID should be set")

		// Break after checking first item (don't need to check all)
		break
	}
}

func TestFetch_ContainsExpectedFields(t *testing.T) {
	// Skip this test in short mode or CI as it requires network access
	if testing.Short() {
		t.Skip("Skipping test that requires network access and git clone")
	}

	result, err := Fetch()
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Check that at least one vulnerability has expected fields
	foundValid := false
	for _, wrapper := range result {
		if wrapper.ID != "" && wrapper.LastUpdated != "" {
			foundValid = true
			break
		}
	}
	assert.True(t, foundValid, "should find at least one valid vulnerability with ID and LastUpdated")
}
