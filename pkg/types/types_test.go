package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertCVSSv3(t *testing.T) {
	type testcase struct {
		vector              string
		baseScore           float64
		impactScore         float64
		exploitabilityScore float64
	}

	for _, c := range []testcase{
		{
			vector:              "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
			baseScore:           8.3,
			impactScore:         6.0,
			exploitabilityScore: 1.6,
		},
		{
			vector:              "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H",
			baseScore:           7.5,
			impactScore:         6.0,
			exploitabilityScore: 0.8,
		},
		{
			vector:              "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
			baseScore:           7.0,
			impactScore:         5.9,
			exploitabilityScore: 1.0,
		},
		{
			vector:              "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			baseScore:           0.0,
			impactScore:         0.0,
			exploitabilityScore: 2.5,
		},
	} {
		t.Run(c.vector, func(t *testing.T) {
			cvssv3, err := ConvertCVSSv3(c.vector)
			assert.NoError(t, err)
			assert.Equal(t, c.baseScore, cvssv3.Score)
			assert.Equal(t, c.impactScore, cvssv3.ImpactScore)
			assert.Equal(t, c.exploitabilityScore, cvssv3.ExploitabilityScore)
		})
	}
}
