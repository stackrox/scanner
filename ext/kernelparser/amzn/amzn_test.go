package amzn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	cases := []struct {
		kernelVersion string
		osImage       string
		expected      *kernelparser.ParseMatch
		valid         bool
	}{
		{
			kernelVersion: "4.14.173-137.229.amzn2.x86_64",
			osImage:       "Amazon Linux 2",

			expected: &kernelparser.ParseMatch{
				Version: "4.14.173-137.229.amzn2.x86_64",
			},
			valid: true,
		},
		{
			kernelVersion: "4.14.171-136.231.amzn2.x86_64",
			osImage:       "Amazon Linux 2",

			expected: &kernelparser.ParseMatch{
				Version: "4.14.171-136.231.amzn2.x86_64",
			},
			valid: true,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.kernelVersion, c.osImage), func(t *testing.T) {
			osImage := strings.ToLower(c.osImage)
			if c.expected != nil {
				c.expected.Namespace = namespace
				c.expected.Format = format
				c.expected.FeatureName = featureName
			}

			match, valid := parser(c.kernelVersion, osImage)
			assert.Equal(t, c.valid, valid)
			assert.Equal(t, c.expected, match)
		})
	}
}
