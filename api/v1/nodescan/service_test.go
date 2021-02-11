package nodescan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDocker(t *testing.T) {
	cases := []struct {
		input  string
		output string
	}{
		{
			input:  "1.12",
			output: "1.12",
		},
		{
			input:  "19.03",
			output: "19.03",
		},
		{
			input:  "19.03.5",
			output: "19.03.5",
		},
		{
			input:  "19.3.5",
			output: "19.03.5",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.input, func(t *testing.T) {
			assert.Equal(t, normalizeDocker(testCase.input), testCase.output)
		})
	}
}
