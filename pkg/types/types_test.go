package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConvertCVSSv3(t *testing.T) {
	cvss3, err := ConvertCVSSv3("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H")
	assert.NoError(t, err)
	assert.Equal(t, 8.3, cvss3.Score)
	assert.Equal(t, 6.0, cvss3.ImpactScore)
	assert.Equal(t, 1.6, cvss3.ExploitabilityScore)

	cvss3, err = ConvertCVSSv3("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H")
	assert.NoError(t, err)
	assert.Equal(t, 7.5, cvss3.Score)
	assert.Equal(t, 6.0, cvss3.ImpactScore)
	assert.Equal(t, 0.8, cvss3.ExploitabilityScore)
}
