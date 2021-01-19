package ubuntu

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
			kernelVersion: "5.9.1-1050",
			osImage:       "Ubuntu 20.04.1 LTS",

			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:20.04",
				Version:     "5.9.1-1050.10000",
				FeatureName: "linux",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-1032-azure",
			osImage:       "Ubuntu 16.04.5 LTS",

			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:16.04",
				Version:     "5.4.0-1032.10000",
				FeatureName: "linux-azure",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-1030-aws",
			osImage:       "Ubuntu 20.04.1 LTS",

			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:20.04",
				Version:     "5.4.0-1030.10000",
				FeatureName: "linux-aws",
			},
			valid: true,
		},
		{
			kernelVersion: "5.3.0-1036-gke",
			osImage:       "Ubuntu 18.04.5 LTS",

			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:18.04",
				Version:     "5.3.0-1036.10000",
				FeatureName: "linux-gke-5.3",
			},
			valid: true,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.kernelVersion, c.osImage), func(t *testing.T) {
			osImage := strings.ToLower(c.osImage)
			if c.expected != nil {
				c.expected.Format = format
			}

			match, valid := parser(c.kernelVersion, osImage)
			assert.Equal(t, c.valid, valid)
			assert.Equal(t, c.expected, match)
		})
	}
}
