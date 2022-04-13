package rhel

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
			kernelVersion: "3.10.0-957.el7.x86_64",
			osImage:       "OpenShift",

			expected: &kernelparser.ParseMatch{
				Namespace: "centos:7",
				Version:   "3.10.0-957.el7.x86_64",
			},
		},
		{
			kernelVersion: "3.10.0-1127.13.1.el7.x86_64",
			osImage:       "Red Hat Enterprise Linux",

			expected: &kernelparser.ParseMatch{
				Namespace: "centos:7",
				Version:   "3.10.0-1127.13.1.el7.x86_64",
			},
		},
		{
			kernelVersion: "3.10.0-1127.13.1.el7.x86_64",
			osImage:       "OpenShift Enterprise",

			expected: &kernelparser.ParseMatch{
				Namespace: "centos:7",
				Version:   "3.10.0-1127.13.1.el7.x86_64",
			},
		},
		{
			kernelVersion: "3.10.0-1062.12.1.el7.x86_64",
			osImage:       "CentOS Linux 7 (Core)",

			expected: &kernelparser.ParseMatch{
				Namespace: "centos:7",
				Version:   "3.10.0-1062.12.1.el7.x86_64",
			},
		},
		{
			kernelVersion: "4.18.0-193.14.3.el8_2.x86_64",
			osImage:       "Red Hat Enterprise Linux CoreOS 45.82.202008101249-0 (Ootpa)",

			expected: nil,
			err:      kernelparser.ErrNodeUnsupported,
		},
		{
			kernelVersion: "5.4.0-5-cloud-amd64",
			osImage:       "Garden Linux 184.0",

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
