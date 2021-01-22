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
		valid         bool
	}{
		{
			kernelVersion: "4.9.0-3-amd64",
			osImage:       "Debian GNU/Linux 9 (stretch)",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:9",
				Version:   "4.9.0-3-amd64",
			},
			valid: true,
		},
		{
			kernelVersion: "4.9.0-13-amd64",
			osImage:       "Debian GNU/Linux 11 (buster)",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:11",
				Version:   "4.9.0-13-amd64",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-5-cloud-amd64",
			osImage:       "Garden Linux 184.0",

			expected: &kernelparser.ParseMatch{
				Namespace: "debian:11",
				Version:   "5.4.0-5-cloud-amd64",
			},
			valid: true,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.kernelVersion, c.osImage), func(t *testing.T) {
			osImage := strings.ToLower(c.osImage)
			if c.expected != nil {
				c.expected.Format = format
				c.expected.FeatureName = featureName
			}

			match, valid := parser(c.kernelVersion, osImage)
			assert.Equal(t, c.valid, valid)
			assert.Equal(t, c.expected, match)
		})
	}
}
