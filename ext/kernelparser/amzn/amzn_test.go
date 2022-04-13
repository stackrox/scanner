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
		err           error
	}{
		{
			kernelVersion: "4.14.173-137.229.amzn2.x86_64",
			osImage:       "Amazon Linux 2",

			expected: &kernelparser.ParseMatch{
				Version: "4.14.173-137.229.amzn2.x86_64",
			},
		},
		{
			kernelVersion: "4.14.171-136.231.amzn2.x86_64",
			osImage:       "Amazon Linux 2",

			expected: &kernelparser.ParseMatch{
				Version: "4.14.171-136.231.amzn2.x86_64",
			},
		},
		{
			kernelVersion: "3.10.0-1127.13.1.el7.x86_64",
			osImage:       "Red Hat Enterprise Linux",

			expected: nil,
			err:      kernelparser.ErrKernelUnrecognized,
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

			match, err := parser(nil, c.kernelVersion, osImage)
			assert.Equal(t, c.expected, match)
			assert.Equal(t, c.err, err)
		})
	}
}
