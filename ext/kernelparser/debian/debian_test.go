package debian

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
			kernelVersion: "4.9.0-3-amd64",
			osImage:       "Debian GNU/Linux 9 (stretch)",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:9",
				Version:   "4.9.0-3-amd64",
			},
		},
		{
			kernelVersion: "4.9.0-13-amd64",
			osImage:       "Debian GNU/Linux 11 (buster)",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:11",
				Version:   "4.9.0-13-amd64",
			},
		},
		{
			kernelVersion: "5.4.0-5-cloud-amd64",
			osImage:       "Garden Linux 184.0",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:11",
				Version:   "5.4.0-5-cloud-amd64",
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
				c.expected.Format = format
				c.expected.FeatureName = featureName
			}

			match, err := parser(nil, c.kernelVersion, osImage)
			assert.Equal(t, c.expected, match)
			assert.Equal(t, c.err, err)
		})
	}
}
