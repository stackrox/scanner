package ubuntu

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/kernelparser"
	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	cases := []struct {
		kernelVersion  string
		osImage        string
		backportExists bool
		expected       *kernelparser.ParseMatch
		valid          bool
	}{
		{
			kernelVersion: "5.9.1-1050",
			osImage:       "Ubuntu 20.04.1 LTS",

			backportExists: false,
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

			backportExists: false,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:16.04",
				Version:     "5.4.0-1032.10000",
				FeatureName: "linux-azure",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-1032-azure",
			osImage:       "Ubuntu 16.04.5 LTS",

			backportExists: true,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:16.04",
				Version:     "5.4.0-1032.10000",
				FeatureName: "linux-azure-5.4",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-1030-aws",
			osImage:       "Ubuntu 20.04.1 LTS",

			backportExists: false,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:20.04",
				Version:     "5.4.0-1030.10000",
				FeatureName: "linux-aws",
			},
			valid: true,
		},
		{
			kernelVersion: "5.4.0-1030-aws",
			osImage:       "Ubuntu 20.04.1 LTS",

			backportExists: true,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:20.04",
				Version:     "5.4.0-1030.10000",
				FeatureName: "linux-aws-5.4",
			},
			valid: true,
		},
		{
			kernelVersion: "5.3.0-1036-gke",
			osImage:       "Ubuntu 18.04.5 LTS",

			backportExists: true,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:18.04",
				Version:     "5.3.0-1036.10000",
				FeatureName: "linux-gke-5.3",
			},
			valid: true,
		},
		{
			kernelVersion: "5.3.0-1036-gke",
			osImage:       "Ubuntu 18.04.5 LTS",

			backportExists: false,
			expected: &kernelparser.ParseMatch{
				Namespace:   "ubuntu:18.04",
				Version:     "5.3.0-1036.10000",
				FeatureName: "linux-gke",
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

			var mockDatastore database.MockDatastore
			mockDatastore.FctFeatureExists = func(_, _ string) (bool, error) {
				return c.backportExists, nil
			}
			match, valid, err := parser(&mockDatastore, c.kernelVersion, osImage)
			assert.NoError(t, err)
			assert.Equal(t, c.valid, valid)
			assert.Equal(t, c.expected, match)
		})
	}
}
